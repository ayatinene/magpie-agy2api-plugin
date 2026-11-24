import crypto from "node:crypto";

export const DEFAULT_BASE_URL = "http://127.0.0.1:8017";
export const SESSION_TTL_MS = 11 * 3600 * 1000;
export const DEFAULT_RATE_LIMIT_BACKOFF_MS = 60 * 1000;

const KNOWN_ERROR_CODES = new Set([
  "invalid_credentials",
  "admin_auth_disabled",
  "login_rate_limited",
  "admin_origin_forbidden",
  "admin_login_required",
  "admin_remote_disabled",
]);

const sessionCache = new Map();
const inFlightLogins = new Map();
const rateLimitUntil = new Map();
const invalidCredsUntil = new Map();
const settingsCache = new Map();
const inFlightSettings = new Map();

export const SETTINGS_CACHE_TTL_MS = 60 * 1000;

export function clearAdminSettingsCache() {
  settingsCache.clear();
  inFlightSettings.clear();
}

export function clearAdminSessionCache() {
  sessionCache.clear();
  inFlightLogins.clear();
  rateLimitUntil.clear();
  invalidCredsUntil.clear();
  clearAdminSettingsCache();
}

export function passwordDigest(raw) {
  return crypto
    .createHash("sha256")
    .update(typeof raw === "string" ? raw : String(raw ?? ""))
    .digest("hex");
}

function makeTaggedError(message, props = {}) {
  const err = new Error(message);
  Object.assign(err, props);
  return err;
}

function abortReason(signal) {
  return signal?.reason ?? new DOMException("The operation was aborted.", "AbortError");
}

export function isLoopbackBaseUrl(rawUrl) {
  try {
    const host = new URL(normalizeBaseUrl(rawUrl)).hostname.toLowerCase();
    return (
      host === "localhost" ||
      host === "::1" ||
      host === "[::1]" ||
      /^127(?:\.\d{1,3}){3}$/.test(host)
    );
  } catch {
    return false;
  }
}

export function normalizeBaseUrl(raw) {
  let url = typeof raw === "string" ? raw.trim() : "";
  if (!url) url = DEFAULT_BASE_URL;
  url = url.replace(/\/+$/, "");
  url = url.replace(/\/(v1beta|v1)$/i, "");
  return url || DEFAULT_BASE_URL;
}

export function resolveAuth(auth, opts = {}) {
  const apiKey = typeof auth?.key === "string" ? auth.key.trim() : "";
  const fallbackBaseUrl =
    typeof opts?.defaultBaseUrl === "string" && opts.defaultBaseUrl.trim()
      ? opts.defaultBaseUrl.trim()
      : DEFAULT_BASE_URL;
  const explicitUrl =
    (typeof auth?.metadata?.baseUrl === "string" && auth.metadata.baseUrl.trim()) ||
    (typeof auth?.baseUrl === "string" && auth.baseUrl.trim()) ||
    "";
  const baseUrl = normalizeBaseUrl(explicitUrl || fallbackBaseUrl);

  const rawUser = auth?.metadata?.adminUsername ?? auth?.adminUsername ?? "admin";
  const adminUsername =
    typeof rawUser === "string" && rawUser.trim() ? rawUser.trim() : "admin";

  const rawPass = auth?.metadata?.adminPassword ?? auth?.adminPassword ?? "";
  const adminPassword = typeof rawPass === "string" ? rawPass : "";

  return {
    apiKey,
    baseUrl,
    adminUsername,
    adminPassword,
  };
}

export function parseRetryAfterMs(headerVal, nowMs = Date.now(), fallbackMs = DEFAULT_RATE_LIMIT_BACKOFF_MS) {
  if (headerVal === undefined || headerVal === null) return fallbackMs;
  const raw = String(headerVal).trim();
  if (!raw) return fallbackMs;
  if (/^\d+(?:\.\d+)?$/.test(raw)) {
    const sec = Number(raw);
    if (Number.isFinite(sec)) {
      return sec > 0 ? Math.ceil(sec * 1000) : 0;
    }
    return fallbackMs;
  }
  const targetMs = Date.parse(raw);
  if (Number.isFinite(targetMs)) {
    return targetMs > nowMs ? targetMs - nowMs : 0;
  }
  return fallbackMs;
}

export function extractAdminCookie(headers) {
  if (!headers) return "";
  const setCookies =
    typeof headers.getSetCookie === "function"
      ? headers.getSetCookie()
      : (() => {
          const single = typeof headers.get === "function" ? headers.get("set-cookie") : null;
          return single ? [single] : [];
        })();

  for (const entry of setCookies) {
    if (typeof entry !== "string") continue;
    const maxAgeMatch = entry.match(/(?:^|;\s*)Max-Age\s*=\s*(-?\d+)/i);
    if (maxAgeMatch && Number(maxAgeMatch[1]) <= 0) {
      continue;
    }
    const match = entry.match(/(?:^|,\s*|;\s*)antigravity_admin=([^;,\s]+)/i);
    if (match && match[1]) {
      return `antigravity_admin=${match[1]}`;
    }
  }
  return "";
}

function sessionKey(baseUrl, adminUsername, adminPassword) {
  const root = normalizeBaseUrl(baseUrl);
  const user = String(adminUsername || "admin").trim() || "admin";
  return `${root}\0${user}\0${passwordDigest(adminPassword)}`;
}

function rateLimitKey(baseUrl, adminUsername) {
  const root = normalizeBaseUrl(baseUrl);
  const user = String(adminUsername || "admin").trim() || "admin";
  return `${root}\0${user}`;
}

async function readKnownErrorCode(res) {
  try {
    const raw = await res.text();
    if (!raw || raw.length > 65536) return "";
    const parsed = JSON.parse(raw);
    const code =
      typeof parsed?.error?.code === "string"
        ? parsed.error.code
        : typeof parsed?.error === "string"
          ? parsed.error
          : "";
    return KNOWN_ERROR_CODES.has(code) ? code : "";
  } catch {
    return "";
  }
}

function awaitSharedWithCallerSignal(entry, signal, inFlightMap, key) {
  if (!signal) {
    entry.waiters++;
    return entry.promise.finally(() => {
      entry.waiters--;
    });
  }
  if (signal.aborted) {
    return Promise.reject(abortReason(signal));
  }
  entry.waiters++;
  return new Promise((resolve, reject) => {
    let done = false;
    const cleanup = () => {
      if (done) return;
      done = true;
      signal.removeEventListener("abort", onAbort);
      entry.waiters--;
    };
    const onAbort = () => {
      cleanup();
      if (entry.waiters <= 0 && !entry.settled) {
        entry.settled = true;
        if (inFlightMap && inFlightMap.get(key) === entry) {
          inFlightMap.delete(key);
        }
        entry.ctl.abort();
      }
      reject(abortReason(signal));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    entry.promise.then(
      (val) => {
        if (done) return;
        cleanup();
        resolve(val);
      },
      (err) => {
        if (done) return;
        cleanup();
        reject(err);
      },
    );
  });
}

export async function loginAdmin(opts = {}) {
  const {
    baseUrl = DEFAULT_BASE_URL,
    adminUsername = "admin",
    adminPassword = "",
    fetchImpl = globalThis.fetch,
    signal,
    timeoutMs = 8000,
    nowFn = Date.now,
    forceRefresh = false,
  } = opts;

  if (signal?.aborted) {
    throw abortReason(signal);
  }
  if (!adminPassword) {
    throw makeTaggedError(
      "Antigravity2API admin credentials are required (configure adminUsername and adminPassword)",
      { kind: "auth" },
    );
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch implementation is unavailable");
  }

  const root = normalizeBaseUrl(baseUrl);
  const user = String(adminUsername || "admin").trim() || "admin";
  const key = sessionKey(root, user, adminPassword);
  const rlKey = rateLimitKey(root, user);
  const now = nowFn();

  if (!forceRefresh) {
    const cached = sessionCache.get(key);
    if (cached && now < cached.expiresAt) {
      return cached.cookie;
    }
  } else {
    sessionCache.delete(key);
  }

  const credBlockedUntil = invalidCredsUntil.get(key);
  if (credBlockedUntil && now < credBlockedUntil) {
    const waitSec = Math.max(1, Math.ceil((credBlockedUntil - now) / 1000));
    throw makeTaggedError(
      `Antigravity2API admin credentials rejected (HTTP 401); retry after ${waitSec}s`,
      { kind: "auth", status: 401, code: "invalid_credentials" },
    );
  }

  const blockedUntil = rateLimitUntil.get(rlKey);
  if (blockedUntil && now < blockedUntil) {
    const waitSec = Math.max(1, Math.ceil((blockedUntil - now) / 1000));
    throw makeTaggedError(
      `Antigravity2API admin login rate limited; retry after ${waitSec}s`,
      { kind: "rate_limit", status: 429 },
    );
  }

  const existingInFlight = inFlightLogins.get(key);
  if (existingInFlight && !existingInFlight.settled && !existingInFlight.ctl.signal.aborted) {
    return awaitSharedWithCallerSignal(existingInFlight, signal, inFlightLogins, key);
  }

  const entry = {
    ctl: new AbortController(),
    waiters: 0,
    settled: false,
    promise: null,
  };
  const timer = setTimeout(() => entry.ctl.abort(), timeoutMs);
  timer.unref?.();

  inFlightLogins.set(key, entry);
  entry.promise = (async () => {
    try {
      const res = await fetchImpl(`${root}/api/session`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({
          username: user,
          password: adminPassword,
        }),
        signal: entry.ctl.signal,
      });

      if (res.status === 429) {
        await res.body?.cancel?.().catch(() => {});
        const retryMs = parseRetryAfterMs(
          res.headers?.get?.("retry-after"),
          nowFn(),
          DEFAULT_RATE_LIMIT_BACKOFF_MS,
        );
        if (retryMs > 0) {
          rateLimitUntil.set(rlKey, nowFn() + retryMs);
        }
        const waitSec = Math.max(1, Math.ceil(retryMs / 1000));
        throw makeTaggedError(
          `Antigravity2API admin login rate limited (HTTP 429); backing off for ${waitSec}s`,
          { kind: "rate_limit", status: 429 },
        );
      }

      if (!res.ok) {
        const errCode = await readKnownErrorCode(res);
        if (res.status === 401) {
          invalidCredsUntil.set(key, nowFn() + DEFAULT_RATE_LIMIT_BACKOFF_MS);
          sessionCache.delete(key);
        }
        const isAuthErr =
          res.status === 401 || res.status === 403 || errCode === "admin_auth_disabled";
        throw makeTaggedError(
          `Antigravity2API admin login failed (HTTP ${res.status})${errCode ? ` (${errCode})` : ""}`,
          {
            kind: isAuthErr ? "auth" : "http",
            status: res.status,
            ...(errCode ? { code: errCode } : {}),
          },
        );
      }

      const cookie = extractAdminCookie(res.headers);
      if (!cookie) {
        throw new Error(
          "Antigravity2API /api/session succeeded but did not return antigravity_admin cookie",
        );
      }

      invalidCredsUntil.delete(key);
      rateLimitUntil.delete(rlKey);
      if (!entry.ctl.signal.aborted) {
        sessionCache.set(key, {
          cookie,
          expiresAt: nowFn() + SESSION_TTL_MS,
        });
      }
      return cookie;
    } finally {
      entry.settled = true;
      clearTimeout(timer);
      if (inFlightLogins.get(key) === entry) {
        inFlightLogins.delete(key);
      }
    }
  })();

  return awaitSharedWithCallerSignal(entry, signal, inFlightLogins, key);
}

function wrapTimedResponse(res, combinedSignal, timer) {
  if (!res?.body || typeof res.body.getReader !== "function") {
    clearTimeout(timer);
    return res;
  }
  const reader = res.body.getReader();
  let cleaned = false;
  let onAbort = null;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    clearTimeout(timer);
    if (onAbort && combinedSignal) {
      combinedSignal.removeEventListener("abort", onAbort);
    }
  };

  const stream = new ReadableStream({
    start(controller) {
      if (combinedSignal.aborted) {
        cleanup();
        reader.cancel().catch(() => {});
        controller.error(abortReason(combinedSignal));
        return;
      }
      onAbort = () => {
        cleanup();
        reader.cancel().catch(() => {});
        try {
          controller.error(abortReason(combinedSignal));
        } catch {
          // already errored/closed
        }
      };
      combinedSignal.addEventListener("abort", onAbort, { once: true });
    },
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          cleanup();
          controller.close();
          return;
        }
        controller.enqueue(value);
      } catch (err) {
        cleanup();
        try {
          controller.error(err);
        } catch {
          // already errored
        }
      }
    },
    async cancel(reason) {
      cleanup();
      try {
        await reader.cancel(reason);
      } catch {
        // ignore
      }
    },
  });

  return new Response(stream, {
    status: res.status,
    statusText: res.statusText,
    headers: res.headers,
  });
}

export async function adminFetch(pathOrUrl, opts = {}) {
  const {
    baseUrl = DEFAULT_BASE_URL,
    adminUsername = "admin",
    adminPassword = "",
    method = "GET",
    body,
    headers: extraHeaders = {},
    fetchImpl = globalThis.fetch,
    signal,
    timeoutMs = 8000,
    nowFn = Date.now,
  } = opts;

  if (signal?.aborted) {
    throw abortReason(signal);
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch implementation is unavailable");
  }

  const root = normalizeBaseUrl(baseUrl);
  const user = String(adminUsername || "admin").trim() || "admin";
  const url = /^https?:\/\//i.test(pathOrUrl)
    ? pathOrUrl
    : `${root}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`;

  const key = sessionKey(root, user, adminPassword);

  const sendRequest = async (cookie) => {
    if (signal?.aborted) {
      throw abortReason(signal);
    }
    const reqHeaders = new Headers(extraHeaders);
    reqHeaders.delete("origin");
    if (!reqHeaders.has("accept")) {
      reqHeaders.set("accept", "application/json");
    }
    if (cookie) {
      reqHeaders.set("cookie", cookie);
    } else {
      reqHeaders.delete("cookie");
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    timer.unref?.();
    const combined = signal ? AbortSignal.any([signal, ctl.signal]) : ctl.signal;
    let res;
    try {
      res = await fetchImpl(url, {
        method,
        headers: reqHeaders,
        ...(body !== undefined ? { body } : {}),
        signal: combined,
      });
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
    return wrapTimedResponse(res, combined, timer);
  };

  if (!adminPassword) {
    const res = await sendRequest("");
    if (res.status === 401 || res.status === 403) {
      await res.body?.cancel?.().catch(() => {});
      throw makeTaggedError(
        res.status === 403
          ? "Antigravity2API admin API forbidden (HTTP 403); verify same-origin or admin credentials"
          : "Antigravity2API admin login required (HTTP 401); configure adminUsername and adminPassword in plugin settings",
        { kind: "auth", status: res.status },
      );
    }
    return res;
  }

  let cookie;
  try {
    cookie = await loginAdmin({
      baseUrl: root,
      adminUsername: user,
      adminPassword,
      fetchImpl,
      signal,
      timeoutMs,
      nowFn,
    });
  } catch (err) {
    if (err?.code === "admin_auth_disabled" && isLoopbackBaseUrl(root)) {
      const anonRes = await sendRequest("");
      if (anonRes.status === 401 || anonRes.status === 403) {
        await anonRes.body?.cancel?.().catch(() => {});
        throw makeTaggedError(
          `Antigravity2API admin API rejected loopback request (HTTP ${anonRes.status})`,
          { kind: "auth", status: anonRes.status },
        );
      }
      return anonRes;
    }
    throw err;
  }

  let res = await sendRequest(cookie);
  if (res.status === 401) {
    await res.body?.cancel?.().catch(() => {});
    const cached = sessionCache.get(key);
    const hadStaleCached = Boolean(cached && cached.cookie === cookie);
    if (hadStaleCached) {
      sessionCache.delete(key);
    }
    try {
      cookie = await loginAdmin({
        baseUrl: root,
        adminUsername: user,
        adminPassword,
        fetchImpl,
        signal,
        timeoutMs,
        nowFn,
        forceRefresh: !sessionCache.has(key),
      });
    } catch (err) {
      if (err?.code === "admin_auth_disabled" && isLoopbackBaseUrl(root)) {
        const anonRes = await sendRequest("");
        if (anonRes.status === 401 || anonRes.status === 403) {
          await anonRes.body?.cancel?.().catch(() => {});
          throw makeTaggedError(
            `Antigravity2API admin API rejected loopback request (HTTP ${anonRes.status})`,
            { kind: "auth", status: anonRes.status },
          );
        }
        return anonRes;
      }
      throw err;
    }
    res = await sendRequest(cookie);
    if (res.status === 401 || res.status === 403) {
      await res.body?.cancel?.().catch(() => {});
      sessionCache.delete(key);
      throw makeTaggedError(
        `Antigravity2API admin API returned HTTP ${res.status} after refreshing session; verify adminUsername and adminPassword`,
        { kind: "auth", status: res.status },
      );
    }
  }

  return res;
}

export function buildAuthScopeKey(authOrBaseUrl) {
  if (typeof authOrBaseUrl === "string" || !authOrBaseUrl || typeof authOrBaseUrl !== "object") {
    const root = normalizeBaseUrl(typeof authOrBaseUrl === "string" ? authOrBaseUrl : DEFAULT_BASE_URL);
    return `${root}\0${passwordDigest("")}\0${passwordDigest("")}`;
  }
  const root = normalizeBaseUrl(authOrBaseUrl.baseUrl);
  const apiKey = typeof authOrBaseUrl.apiKey === "string" ? authOrBaseUrl.apiKey.trim() : "";
  const user = String(authOrBaseUrl.adminUsername || "admin").trim() || "admin";
  const pass = typeof authOrBaseUrl.adminPassword === "string" ? authOrBaseUrl.adminPassword : "";
  return `${root}\0${passwordDigest(apiKey)}\0${passwordDigest(`${user}\0${pass}`)}`;
}

function emptyParsedSettings() {
  return {
    modelMapping: new Map(),
    apiKeys: new Set(),
    apiKeyAccounts: new Map(),
    quotaReserveFraction: 0,
  };
}

function parseLastColonPairs(rawValue) {
  const pairs = [];
  if (typeof rawValue === "string") {
    for (const part of rawValue.split(",")) {
      const item = part.trim();
      if (!item) continue;
      const idx = item.lastIndexOf(":");
      if (idx <= 0) continue;
      const left = item.slice(0, idx).trim();
      const right = item.slice(idx + 1).trim();
      if (left && right) pairs.push([left, right]);
    }
  } else if (rawValue && typeof rawValue === "object" && !Array.isArray(rawValue)) {
    for (const [k, v] of Object.entries(rawValue)) {
      const left = String(k || "").trim();
      const right = typeof v === "string" ? v.trim() : "";
      if (left && right) pairs.push([left, right]);
    }
  }
  return pairs;
}

export function parseAdminSettingsPayload(payload) {
  const out = emptyParsedSettings();
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return out;
  }
  const raw =
    payload.values && typeof payload.values === "object" && !Array.isArray(payload.values)
      ? payload.values
      : payload.settings && typeof payload.settings === "object" && !Array.isArray(payload.settings)
        ? payload.settings
        : payload.data && typeof payload.data === "object" && !Array.isArray(payload.data)
          ? payload.data
          : payload;

  for (const [alias, target] of parseLastColonPairs(raw.MODEL_MAPPING)) {
    if (!out.modelMapping.has(alias)) {
      out.modelMapping.set(alias, target);
    }
  }

  const rawKeys = raw.API_KEYS;
  if (typeof rawKeys === "string") {
    for (const k of rawKeys.split(",")) {
      const trimmed = k.trim();
      if (trimmed) out.apiKeys.add(trimmed);
    }
  } else if (Array.isArray(rawKeys)) {
    for (const k of rawKeys) {
      if (typeof k === "string" && k.trim()) out.apiKeys.add(k.trim());
    }
  }

  for (const [key, accList] of parseLastColonPairs(raw.API_KEY_ACCOUNTS)) {
    if (out.apiKeyAccounts.has(key)) continue;
    const set = new Set();
    for (const acc of accList.split("|")) {
      const trimmed = acc.trim();
      if (trimmed) set.add(trimmed);
    }
    if (set.size > 0) {
      out.apiKeyAccounts.set(key, set);
    }
  }

  const rawReserve = raw.QUOTA_RESERVE_PERCENT;
  if (rawReserve !== undefined && rawReserve !== null && String(rawReserve).trim() !== "") {
    const n = Number(rawReserve);
    if (Number.isFinite(n) && n >= 0 && n <= 99) {
      out.quotaReserveFraction = n / 100;
    }
  }

  return out;
}

export function resolveAllowedAccountsForApiKey(settings, apiKey) {
  const key = typeof apiKey === "string" ? apiKey.trim() : "";
  if (!settings || !key || !(settings.apiKeys instanceof Set) || settings.apiKeys.size === 0) {
    return null;
  }
  if (!settings.apiKeys.has(key)) {
    return null;
  }
  const bound = settings.apiKeyAccounts?.get?.(key);
  return bound && bound.size > 0 ? new Set(bound) : null;
}

export async function fetchAdminSettingsCached(opts = {}) {
  const {
    baseUrl = DEFAULT_BASE_URL,
    adminUsername = "admin",
    adminPassword = "",
    fetchImpl = globalThis.fetch,
    signal,
    timeoutMs = 3000,
    nowFn = Date.now,
    ttlMs = SETTINGS_CACHE_TTL_MS,
  } = opts;

  if (typeof fetchImpl !== "function" || signal?.aborted) {
    return emptyParsedSettings();
  }

  const root = normalizeBaseUrl(baseUrl);
  const user = String(adminUsername || "admin").trim() || "admin";
  const cacheKey = `${root}\0${user}\0${passwordDigest(adminPassword)}`;
  const now = nowFn();

  if (ttlMs > 0) {
    const cached = settingsCache.get(cacheKey);
    if (cached && now - cached.fetchedAt < ttlMs) {
      return cached.settings;
    }
  }

  if (!signal && inFlightSettings.has(cacheKey)) {
    return inFlightSettings.get(cacheKey);
  }

  const promise = (async () => {
    try {
      const res = await adminFetch("/api/settings", {
        baseUrl: root,
        adminUsername: user,
        adminPassword,
        method: "GET",
        fetchImpl,
        signal,
        timeoutMs,
        nowFn,
      });
      if (!res.ok) {
        await res.body?.cancel?.().catch(() => {});
        const empty = emptyParsedSettings();
        if (res.status === 404 && ttlMs > 0) {
          settingsCache.set(cacheKey, { fetchedAt: nowFn(), settings: empty });
        }
        return empty;
      }
      const data = await res.json();
      const parsed = parseAdminSettingsPayload(data);
      if (ttlMs > 0) {
        settingsCache.set(cacheKey, { fetchedAt: nowFn(), settings: parsed });
      }
      return parsed;
    } catch {
      return emptyParsedSettings();
    } finally {
      if (!signal && inFlightSettings.get(cacheKey) === promise) {
        inFlightSettings.delete(cacheKey);
      }
    }
  })();

  if (!signal) {
    inFlightSettings.set(cacheKey, promise);
  }
  return promise;
}
