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

export function clearAdminSessionCache() {
  sessionCache.clear();
  inFlightLogins.clear();
  rateLimitUntil.clear();
  invalidCredsUntil.clear();
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
      throw makeTaggedError(
        `Antigravity2API admin API returned HTTP ${res.status} after refreshing session; verify adminUsername and adminPassword`,
        { kind: "auth", status: res.status },
      );
    }
  }

  return res;
}
