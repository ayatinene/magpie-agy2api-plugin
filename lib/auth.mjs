export const DEFAULT_BASE_URL = "http://127.0.0.1:8017";
export const SESSION_TTL_MS = 11 * 3600 * 1000;
export const DEFAULT_RATE_LIMIT_BACKOFF_MS = 60 * 1000;

const sessionCache = new Map();
const inFlightLogins = new Map();
const rateLimitUntil = new Map();

export function clearAdminSessionCache() {
  sessionCache.clear();
  inFlightLogins.clear();
  rateLimitUntil.clear();
}

export function normalizeBaseUrl(raw) {
  let url = typeof raw === "string" ? raw.trim() : "";
  if (!url) url = DEFAULT_BASE_URL;
  url = url.replace(/\/+$/, "");
  url = url.replace(/\/(v1beta|v1)$/i, "");
  return url || DEFAULT_BASE_URL;
}

export function resolveAuth(auth) {
  const apiKey = typeof auth?.key === "string" ? auth.key.trim() : "";
  const rawUrl = auth?.metadata?.baseUrl ?? auth?.baseUrl ?? DEFAULT_BASE_URL;
  const baseUrl = normalizeBaseUrl(rawUrl);

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
    if (Number.isFinite(sec) && sec > 0) {
      return Math.ceil(sec * 1000);
    }
    return fallbackMs;
  }
  const targetMs = Date.parse(raw);
  if (Number.isFinite(targetMs) && targetMs > nowMs) {
    return targetMs - nowMs;
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
    const match = entry.match(/(?:^|,\s*|;\s*)antigravity_admin=([^;,\s]+)/i);
    if (match && match[1]) {
      return `antigravity_admin=${match[1]}`;
    }
  }
  return "";
}

function sessionKey(baseUrl, adminUsername) {
  return `${normalizeBaseUrl(baseUrl)}\0${adminUsername || "admin"}`;
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

  if (!adminPassword) {
    throw new Error(
      "Antigravity2API admin credentials are required (configure adminUsername and adminPassword)",
    );
  }
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch implementation is unavailable");
  }

  const root = normalizeBaseUrl(baseUrl);
  const key = sessionKey(root, adminUsername);
  const now = nowFn();

  if (!forceRefresh) {
    const cached = sessionCache.get(key);
    if (cached && cached.passwordKey === adminPassword && now < cached.expiresAt) {
      return cached.cookie;
    }
  } else {
    sessionCache.delete(key);
  }

  const blockedUntil = rateLimitUntil.get(key);
  if (blockedUntil && now < blockedUntil) {
    const waitSec = Math.max(1, Math.ceil((blockedUntil - now) / 1000));
    throw new Error(
      `Antigravity2API admin login rate limited; retry after ${waitSec}s`,
    );
  }

  if (inFlightLogins.has(key)) {
    return inFlightLogins.get(key);
  }

  const run = (async () => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    const combined = signal ? AbortSignal.any([signal, ctl.signal]) : ctl.signal;
    try {
      const res = await fetchImpl(`${root}/api/session`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({
          username: adminUsername,
          password: adminPassword,
        }),
        signal: combined,
      });

      if (res.status === 429) {
        const retryMs = parseRetryAfterMs(
          res.headers?.get?.("retry-after"),
          nowFn(),
          DEFAULT_RATE_LIMIT_BACKOFF_MS,
        );
        rateLimitUntil.set(key, nowFn() + retryMs);
        const waitSec = Math.max(1, Math.ceil(retryMs / 1000));
        throw new Error(
          `Antigravity2API admin login rate limited (HTTP 429); backing off for ${waitSec}s`,
        );
      }

      if (!res.ok) {
        let detail = "";
        try {
          detail = await res.text();
        } catch {
          detail = "";
        }
        throw new Error(
          `Antigravity2API admin login failed (HTTP ${res.status})${detail ? `: ${detail.slice(0, 200)}` : ""}`,
        );
      }

      const cookie = extractAdminCookie(res.headers);
      if (!cookie) {
        throw new Error("Antigravity2API /api/session succeeded but did not return antigravity_admin cookie");
      }

      rateLimitUntil.delete(key);
      sessionCache.set(key, {
        cookie,
        passwordKey: adminPassword,
        expiresAt: nowFn() + SESSION_TTL_MS,
      });
      return cookie;
    } finally {
      clearTimeout(timer);
      inFlightLogins.delete(key);
    }
  })();

  inFlightLogins.set(key, run);
  return run;
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

  if (typeof fetchImpl !== "function") {
    throw new Error("fetch implementation is unavailable");
  }

  const root = normalizeBaseUrl(baseUrl);
  const url = /^https?:\/\//i.test(pathOrUrl)
    ? pathOrUrl
    : `${root}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`;

  const key = sessionKey(root, adminUsername);

  const sendRequest = async (cookie) => {
    const reqHeaders = new Headers(extraHeaders);
    reqHeaders.delete("origin");
    if (!reqHeaders.has("accept")) {
      reqHeaders.set("accept", "application/json");
    }
    if (cookie) {
      reqHeaders.set("cookie", cookie);
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    const combined = signal ? AbortSignal.any([signal, ctl.signal]) : ctl.signal;
    try {
      return await fetchImpl(url, {
        method,
        headers: reqHeaders,
        ...(body !== undefined ? { body } : {}),
        signal: combined,
      });
    } finally {
      clearTimeout(timer);
    }
  };

  if (!adminPassword) {
    const res = await sendRequest("");
    if (res.status === 401) {
      throw new Error(
        "Antigravity2API admin login required (HTTP 401); configure adminUsername and adminPassword in plugin settings",
      );
    }
    return res;
  }

  let cookie = await loginAdmin({
    baseUrl: root,
    adminUsername,
    adminPassword,
    fetchImpl,
    signal,
    timeoutMs,
    nowFn,
  });

  let res = await sendRequest(cookie);
  if (res.status === 401) {
    // Drain body before retrying
    try {
      await res.text();
    } catch {
      // ignore
    }
    sessionCache.delete(key);
    cookie = await loginAdmin({
      baseUrl: root,
      adminUsername,
      adminPassword,
      fetchImpl,
      signal,
      timeoutMs,
      nowFn,
      forceRefresh: true,
    });
    res = await sendRequest(cookie);
    if (res.status === 401) {
      throw new Error(
        "Antigravity2API admin API returned HTTP 401 after refreshing session; verify adminUsername and adminPassword",
      );
    }
  }

  return res;
}
