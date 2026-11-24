import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";

import plugin, { OFFICIAL_ICON_URL } from "../index.mjs";
import {
  DEFAULT_BASE_URL,
  adminFetch,
  clearAdminSessionCache,
  loginAdmin,
  normalizeBaseUrl,
  resolveAuth,
} from "../lib/auth.mjs";
import {
  buildModelsFromRawEntries,
  clearModelCache,
  getDiscoveredModels,
  getModelQuotaGroupMap,
  isXhighGeminiModel,
  reconcileModels,
} from "../lib/models.mjs";
import {
  clearQuotaCache,
  computeAgy2ApiUsage,
  extractAccountGroupQuota,
  extractAccountPoolQuota,
  getAgy2ApiUsage,
  resolveAccountPool,
} from "../lib/quota.mjs";
import {
  clearPrefixEffortCache,
  createAgy2ApiFetch,
  detectProtocol,
  hasWholeModelToken,
  normalizeUpstreamErrorResponse,
  rewriteUpstreamUrl,
} from "../lib/fetch.mjs";

function makeJsonResponse(body, status = 200, headers = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

describe("auth.mjs", () => {
  beforeEach(() => {
    clearAdminSessionCache();
  });

  it("resolves defaults and strips trailing slashes and /v1 or /v1beta", () => {
    assert.equal(DEFAULT_BASE_URL, "http://127.0.0.1:8017");
    assert.equal(normalizeBaseUrl("http://127.0.0.1:8017/v1beta/"), "http://127.0.0.1:8017");
    assert.equal(normalizeBaseUrl("http://127.0.0.1:8017/v1"), "http://127.0.0.1:8017");

    const resolved = resolveAuth({
      key: " sk-public-123 ",
      metadata: {
        baseUrl: "http://127.0.0.1:8017/v1/",
        adminUsername: "ops-admin",
        adminPassword: "secret-password",
      },
    });
    assert.deepEqual(resolved, {
      apiKey: "sk-public-123",
      baseUrl: "http://127.0.0.1:8017",
      adminUsername: "ops-admin",
      adminPassword: "secret-password",
    });

    const defaults = resolveAuth({ key: "sk-1" });
    assert.deepEqual(defaults, {
      apiKey: "sk-1",
      baseUrl: "http://127.0.0.1:8017",
      adminUsername: "admin",
      adminPassword: "",
    });
  });

  it("logs in via POST /api/session without Origin header, caches 11h cookie, and coalesces concurrent logins", async () => {
    let loginCalls = 0;
    let now = 1_700_000_000_000;
    const fetchImpl = async (url, init) => {
      assert.equal(url, "http://127.0.0.1:8017/api/session");
      assert.equal(init.method, "POST");
      const hdrs = new Headers(init.headers);
      assert.equal(hdrs.get("origin"), null);
      assert.deepEqual(JSON.parse(init.body), { username: "admin", password: "pw1" });
      loginCalls++;
      await new Promise((r) => setTimeout(r, 10));
      return new Response("{}", {
        status: 200,
        headers: {
          "set-cookie": "antigravity_admin=tok-abc-123; Path=/api; Max-Age=43200; HttpOnly; SameSite=Strict",
        },
      });
    };

    const [c1, c2] = await Promise.all([
      loginAdmin({ baseUrl: DEFAULT_BASE_URL, adminUsername: "admin", adminPassword: "pw1", fetchImpl, nowFn: () => now }),
      loginAdmin({ baseUrl: DEFAULT_BASE_URL, adminUsername: "admin", adminPassword: "pw1", fetchImpl, nowFn: () => now }),
    ]);
    assert.equal(c1, "antigravity_admin=tok-abc-123");
    assert.equal(c2, "antigravity_admin=tok-abc-123");
    assert.equal(loginCalls, 1);

    // Still cached after 10 hours
    now += 10 * 3600 * 1000;
    const c3 = await loginAdmin({
      baseUrl: DEFAULT_BASE_URL,
      adminUsername: "admin",
      adminPassword: "pw1",
      fetchImpl,
      nowFn: () => now,
    });
    assert.equal(c3, "antigravity_admin=tok-abc-123");
    assert.equal(loginCalls, 1);

    // Expired after 11 hours
    now += 2 * 3600 * 1000;
    const c4 = await loginAdmin({
      baseUrl: DEFAULT_BASE_URL,
      adminUsername: "admin",
      adminPassword: "pw1",
      fetchImpl,
      nowFn: () => now,
    });
    assert.equal(c4, "antigravity_admin=tok-abc-123");
    assert.equal(loginCalls, 2);
  });

  it("retries admin call once after 401 by refreshing session cookie", async () => {
    let loginCount = 0;
    let accountCalls = 0;
    const fetchImpl = async (url, init) => {
      if (url.endsWith("/api/session")) {
        loginCount++;
        return new Response("{}", {
          status: 200,
          headers: {
            "set-cookie": `antigravity_admin=tok-${loginCount}; Path=/api; HttpOnly`,
          },
        });
      }
      if (url.endsWith("/api/accounts")) {
        accountCalls++;
        const hdrs = new Headers(init.headers);
        if (hdrs.get("cookie") === "antigravity_admin=tok-1") {
          return makeJsonResponse({ error: "admin_login_required" }, 401);
        }
        assert.equal(hdrs.get("cookie"), "antigravity_admin=tok-2");
        return makeJsonResponse({ accounts: [] }, 200);
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const res = await adminFetch("/api/accounts", {
      baseUrl: DEFAULT_BASE_URL,
      adminUsername: "admin",
      adminPassword: "secret",
      fetchImpl,
    });
    assert.equal(res.status, 200);
    assert.equal(loginCount, 2);
    assert.equal(accountCalls, 2);
  });

  it("respects Retry-After backoff on 429 login_rate_limited", async () => {
    let loginCount = 0;
    let now = 1_700_000_000_000;
    const fetchImpl = async () => {
      loginCount++;
      if (loginCount === 1) {
        return new Response(JSON.stringify({ error: "login_rate_limited" }), {
          status: 429,
          headers: { "retry-after": "45" },
        });
      }
      return new Response("{}", {
        status: 200,
        headers: { "set-cookie": "antigravity_admin=tok-ok; Path=/api" },
      });
    };

    await assert.rejects(
      () =>
        loginAdmin({
          baseUrl: DEFAULT_BASE_URL,
          adminUsername: "admin",
          adminPassword: "pw",
          fetchImpl,
          nowFn: () => now,
        }),
      /429|rate limited/i,
    );
    assert.equal(loginCount, 1);

    // Immediate retry within 45s backoff should not hit network
    now += 10_000;
    await assert.rejects(
      () =>
        loginAdmin({
          baseUrl: DEFAULT_BASE_URL,
          adminUsername: "admin",
          adminPassword: "pw",
          fetchImpl,
          nowFn: () => now,
        }),
      /retry after/i,
    );
    assert.equal(loginCount, 1);

    // After backoff expires, login succeeds
    now += 40_000;
    const cookie = await loginAdmin({
      baseUrl: DEFAULT_BASE_URL,
      adminUsername: "admin",
      adminPassword: "pw",
      fetchImpl,
      nowFn: () => now,
    });
    assert.equal(cookie, "antigravity_admin=tok-ok");
    assert.equal(loginCount, 2);
  });

  it("allows loopback admin calls without password, or returns clear error on 401", async () => {
    const okFetch = async (url, init) => {
      const hdrs = new Headers(init.headers);
      assert.equal(hdrs.get("cookie"), null);
      return makeJsonResponse({ accounts: [{ id: "alice@example.com", state: "ready" }] }, 200);
    };
    const res = await adminFetch("/api/accounts", {
      baseUrl: DEFAULT_BASE_URL,
      adminPassword: "",
      fetchImpl: okFetch,
    });
    assert.equal(res.status, 200);

    const unauthFetch = async () => makeJsonResponse({ error: "admin_login_required" }, 401);
    await assert.rejects(
      () =>
        adminFetch("/api/accounts", {
          baseUrl: DEFAULT_BASE_URL,
          adminPassword: "",
          fetchImpl: unauthFetch,
        }),
      /configure adminUsername and adminPassword/i,
    );
  });

  it("does not hand a successful in-flight cookie to another password or leak upstream error text", async () => {
    let calls = 0;
    const fetchImpl = async (url, init) => {
      assert.equal(new URL(url).pathname, "/api/session");
      calls++;
      await Promise.resolve();
      if (JSON.parse(init.body).password === "fixture-correct") {
        return makeJsonResponse(
          {},
          200,
          { "set-cookie": "antigravity_admin=fixture-cookie; Path=/api; Max-Age=43200" },
        );
      }
      return makeJsonResponse(
        { error: { code: "invalid_credentials", message: "fixture-body-must-not-leak" } },
        401,
      );
    };
    const results = await Promise.allSettled(
      ["fixture-correct", "fixture-wrong"].map((adminPassword) =>
        loginAdmin({ baseUrl: "https://auth.example.invalid", adminPassword, fetchImpl }),
      ),
    );
    assert.deepEqual(
      results.map((x) => x.status),
      ["fulfilled", "rejected"],
    );
    assert.equal(results[0].value, "antigravity_admin=fixture-cookie");
    assert.doesNotMatch(results[1].reason.message, /fixture-body-must-not-leak/);
    assert.equal(calls, 2);
  });

  it("cancels individual login waiters independently and aborts shared request only when all waiters cancel", async () => {
    let calls = 0;
    let sharedSignalAborted = false;
    let resolveFetch;
    const fetchImpl = (url, init) => {
      calls++;
      init.signal.addEventListener("abort", () => {
        sharedSignalAborted = true;
      });
      return new Promise((resolve, reject) => {
        resolveFetch = resolve;
        init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
      });
    };

    const ctl1 = new AbortController();
    const ctl2 = new AbortController();
    const p1 = loginAdmin({
      baseUrl: "https://auth-cancel.example.invalid",
      adminPassword: "fixture-pw",
      signal: ctl1.signal,
      fetchImpl,
    });
    const p2 = loginAdmin({
      baseUrl: "https://auth-cancel.example.invalid",
      adminPassword: "fixture-pw",
      signal: ctl2.signal,
      fetchImpl,
    });

    ctl1.abort();
    await assert.rejects(() => p1);
    assert.equal(sharedSignalAborted, false);

    resolveFetch(
      makeJsonResponse({}, 200, { "set-cookie": "antigravity_admin=fixture-ok; Path=/api" }),
    );
    assert.equal(await p2, "antigravity_admin=fixture-ok");
    assert.equal(calls, 1);

    // When all waiters abort, shared signal aborts and immediate next call (started before awaiting p3) starts fresh and succeeds
    sharedSignalAborted = false;
    const ctl3 = new AbortController();
    const p3 = loginAdmin({
      baseUrl: "https://auth-cancel-2.example.invalid",
      adminPassword: "fixture-pw",
      signal: ctl3.signal,
      fetchImpl,
    });
    ctl3.abort();
    assert.equal(sharedSignalAborted, true);

    let secondCompleted = false;
    const p4 = loginAdmin({
      baseUrl: "https://auth-cancel-2.example.invalid",
      adminPassword: "fixture-pw",
      fetchImpl: async () => {
        secondCompleted = true;
        return makeJsonResponse({}, 200, { "set-cookie": "antigravity_admin=fixture-fresh; Path=/api" });
      },
    });
    const [r3, r4] = await Promise.allSettled([p3, p4]);
    assert.equal(r3.status, "rejected");
    assert.equal(r4.status, "fulfilled");
    assert.equal(r4.value, "antigravity_admin=fixture-fresh");
    assert.equal(secondCompleted, true);
  });

  it("recovers in-flight coalescing after sync throw, scopes 429 by root+user (not origin), and reports 403 cleanly", async () => {
    let attempt = 0;
    const syncThrowThenOk = () => {
      attempt++;
      if (attempt === 1) {
        throw new Error("sync network boom");
      }
      return Promise.resolve(
        makeJsonResponse({}, 200, { "set-cookie": "antigravity_admin=tok-sync-ok; Path=/api" }),
      );
    };
    await assert.rejects(
      () =>
        loginAdmin({
          baseUrl: "https://sync-throw.example.invalid",
          adminPassword: "pw",
          fetchImpl: syncThrowThenOk,
        }),
      /sync network boom/,
    );
    const recovered = await loginAdmin({
      baseUrl: "https://sync-throw.example.invalid",
      adminPassword: "pw",
      fetchImpl: syncThrowThenOk,
    });
    assert.equal(recovered, "antigravity_admin=tok-sync-ok");
    assert.equal(attempt, 2);

    // 429 on /a does NOT block /b on same origin with different root/user
    const seenUrls = [];
    const multiRootFetch = async (url) => {
      seenUrls.push(String(url));
      if (String(url).includes("/a/")) {
        return new Response(JSON.stringify({ error: "login_rate_limited" }), {
          status: 429,
          headers: { "retry-after": "60" },
        });
      }
      return makeJsonResponse({}, 200, { "set-cookie": "antigravity_admin=tok-b; Path=/api" });
    };
    await assert.rejects(() =>
      loginAdmin({
        baseUrl: "https://shared-origin.example.invalid/a",
        adminUsername: "user-a",
        adminPassword: "pw",
        fetchImpl: multiRootFetch,
      }),
    );
    const bCookie = await loginAdmin({
      baseUrl: "https://shared-origin.example.invalid/b",
      adminUsername: "user-b",
      adminPassword: "pw",
      fetchImpl: multiRootFetch,
    });
    assert.equal(bCookie, "antigravity_admin=tok-b");
    assert.equal(seenUrls.length, 2);

    // Anonymous 403 error message reports 403 (not hardcoded 401)
    await assert.rejects(
      () =>
        adminFetch("/api/accounts", {
          baseUrl: DEFAULT_BASE_URL,
          adminPassword: "",
          fetchImpl: async () => makeJsonResponse({ error: "admin_origin_forbidden" }, 403),
        }),
      /403/,
    );
  });

  it("backs off 60s on 401 invalid_credentials per credential scope without blocking other passwords", async () => {
    let now = 1_700_000_000_000;
    let calls = 0;
    const fetchImpl = async (_url, init) => {
      calls++;
      if (JSON.parse(init.body).password === "fixture-right") {
        return makeJsonResponse({}, 200, { "set-cookie": "antigravity_admin=fixture-tok; Path=/api" });
      }
      return makeJsonResponse({ error: { code: "invalid_credentials" } }, 401);
    };

    await assert.rejects(() =>
      loginAdmin({
        baseUrl: "https://backoff.example.invalid",
        adminPassword: "fixture-wrong",
        fetchImpl,
        nowFn: () => now,
      }),
    );
    assert.equal(calls, 1);

    // Same wrong password within 60s -> blocked without POST
    now += 10_000;
    await assert.rejects(() =>
      loginAdmin({
        baseUrl: "https://backoff.example.invalid",
        adminPassword: "fixture-wrong",
        fetchImpl,
        nowFn: () => now,
      }),
    );
    assert.equal(calls, 1);

    // Correct password succeeds immediately without being blocked
    const cookie = await loginAdmin({
      baseUrl: "https://backoff.example.invalid",
      adminPassword: "fixture-right",
      fetchImpl,
      nowFn: () => now,
    });
    assert.equal(cookie, "antigravity_admin=fixture-tok");
    assert.equal(calls, 2);
  });

  it("falls back to cookie-less request on loopback when login returns admin_auth_disabled, and rejects on remote", async () => {
    const loopFetch = async (url, init) => {
      if (url.endsWith("/api/session")) {
        return makeJsonResponse({ error: { code: "admin_auth_disabled" } }, 400);
      }
      const hdrs = new Headers(init.headers);
      assert.equal(hdrs.get("cookie"), null);
      return makeJsonResponse({ accounts: [] }, 200);
    };
    const res = await adminFetch("/api/accounts", {
      baseUrl: DEFAULT_BASE_URL,
      adminPassword: "fixture-pw",
      fetchImpl: loopFetch,
    });
    assert.equal(res.status, 200);

    let remoteGets = 0;
    const remoteFetch = async (url) => {
      if (url.endsWith("/api/session")) {
        return makeJsonResponse({ error: { code: "admin_auth_disabled" } }, 400);
      }
      remoteGets++;
      return makeJsonResponse({ accounts: [] }, 200);
    };
    await assert.rejects(
      () =>
        adminFetch("/api/accounts", {
          baseUrl: "https://remote.example.invalid",
          adminPassword: "fixture-pw",
          fetchImpl: remoteFetch,
        }),
      /admin_auth_disabled/i,
    );
    assert.equal(remoteGets, 0);
  });

  it("enforces adminFetch timeout and caller signal while reading response body", async () => {
    const hangingFetch = (_url, init) => {
      const stream = new ReadableStream({
        start(controller) {
          init.signal.addEventListener(
            "abort",
            () => controller.error(new DOMException("Aborted", "AbortError")),
            { once: true },
          );
        },
      });
      return Promise.resolve(
        new Response(stream, { status: 200, headers: { "content-type": "application/json" } }),
      );
    };

    const timedRes = await adminFetch("/api/accounts", {
      baseUrl: DEFAULT_BASE_URL,
      adminPassword: "",
      timeoutMs: 25,
      fetchImpl: hangingFetch,
    });
    await assert.rejects(() => timedRes.json());

    const ctl = new AbortController();
    const sigRes = await adminFetch("/api/accounts", {
      baseUrl: DEFAULT_BASE_URL,
      adminPassword: "",
      timeoutMs: 5000,
      signal: ctl.signal,
      fetchImpl: hangingFetch,
    });
    setTimeout(() => ctl.abort(), 15);
    await assert.rejects(() => sigRes.json());
  });

  it("clears sessionCache when adminFetch retry after 401 still gets 401 or 403", async () => {
    for (const retryStatus of [401, 403]) {
      clearAdminSessionCache();
      let loginCalls = 0;
      let accountCalls = 0;
      let failRetry = true;
      const fetchImpl = async (url) => {
        if (url.endsWith("/api/session")) {
          loginCalls++;
          return makeJsonResponse(
            {},
            200,
            { "set-cookie": `antigravity_admin=tok-${loginCalls}; Path=/api` },
          );
        }
        if (url.endsWith("/api/accounts")) {
          accountCalls++;
          if (failRetry) {
            return makeJsonResponse(
              { error: retryStatus === 401 ? "admin_login_required" : "forbidden" },
              accountCalls === 1 ? 401 : retryStatus,
            );
          }
          return makeJsonResponse({ accounts: [] }, 200);
        }
        throw new Error(`Unexpected URL: ${url}`);
      };

      await assert.rejects(
        () =>
          adminFetch("/api/accounts", {
            baseUrl: "https://clear-cache.example.invalid",
            adminPassword: "pw",
            fetchImpl,
          }),
        new RegExp(`HTTP ${retryStatus}`),
      );
      assert.equal(loginCalls, 2);

      // Next call must re-login because the second cookie was evicted from sessionCache
      failRetry = false;
      const okRes = await adminFetch("/api/accounts", {
        baseUrl: "https://clear-cache.example.invalid",
        adminPassword: "pw",
        fetchImpl,
      });
      assert.equal(okRes.status, 200);
      assert.equal(loginCalls, 3);
    }
  });
});

describe("models.mjs", () => {
  beforeEach(() => {
    clearAdminSessionCache();
    clearModelCache();
  });

  it("discovers models dynamically from GET /api/models with cookie auth and expands thinking_levels by default", async () => {
    const remoteRoot = "https://models.example.invalid";
    const paths = [];
    const fetchImpl = async (url, init) => {
      paths.push(new URL(url).pathname);
      if (url.endsWith("/api/session")) {
        return new Response("{}", {
          status: 200,
          headers: { "set-cookie": "antigravity_admin=sess1; Path=/api" },
        });
      }
      if (url.endsWith("/api/models")) {
        const hdrs = new Headers(init?.headers);
        if (hdrs.get("cookie") !== "antigravity_admin=sess1") {
          return makeJsonResponse({ error: "admin_login_required" }, 401);
        }
        return makeJsonResponse({
          models: [
            {
              id: "gemini-4-neon",
              name: "Gemini 4 Neon",
              input_token_limit: 1048576,
              output_token_limit: 262144,
              capabilities: { images: true, thinking: true, video: true, image_generation: false },
              provider: "MODEL_PROVIDER_GOOGLE",
              quota_group: "gemini",
              thinking_levels: ["low", "medium", "high", "xhigh"],
              default_thinking_level: "medium",
            },
            {
              id: "claude-opus-5-5",
              name: "Claude Opus 5.5",
              input_token_limit: 200000,
              output_token_limit: 64000,
              capabilities: { images: true, thinking: true },
              provider: "MODEL_PROVIDER_ANTHROPIC",
              quota_group: "3p",
              thinking_levels: ["low", "high"],
            },
            {
              id: "gpt-oss-120b",
              name: "GPT OSS 120B",
              input_token_limit: 131072,
              output_token_limit: 32768,
              capabilities: { thinking: true },
              provider: "MODEL_PROVIDER_OPENAI",
              quota_group: "3p",
              thinking_levels: ["low", "medium", "high"],
            },
            {
              id: "custom-future-argon",
              name: "Custom Future Argon",
              input_token_limit: 500000,
              output_token_limit: 65536,
              capabilities: { images: true, thinking: false },
              provider: "MODEL_PROVIDER_GOOGLE",
              quota_group: "gemini-argon-wtu",
            },
          ],
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    };

    const models = await reconcileModels(
      {},
      {
        auth: {
          key: "sk-pub",
          metadata: {
            baseUrl: remoteRoot,
            adminUsername: "admin",
            adminPassword: "pw",
          },
        },
      },
      { fetchImpl, foldEffortVariants: false },
    );

    assert.deepEqual(paths, ["/api/session", "/api/models", "/api/settings"]);

    // Base models + expanded effort models
    assert.ok(models["gemini-4-neon"]);
    assert.deepEqual(Object.keys(models["gemini-4-neon"].variants), [
      "low",
      "medium",
      "high",
      "xhigh",
    ]);
    assert.equal(models["gemini-4-neon"].api.npm, "@ai-sdk/google");
    assert.equal(models["gemini-4-neon"].api.url, `${remoteRoot}/v1beta`);
    assert.equal(models["gemini-4-neon"].providerID, "agy2api");
    assert.equal(models["gemini-4-neon"].capabilities.input.video, true);
    assert.equal(models["gemini-4-neon"].capabilities.input.image, true);

    assert.ok(models["gemini-4-neon-low"]);
    assert.ok(models["gemini-4-neon-xhigh"]);
    assert.equal(models["gemini-4-neon-xhigh"].name, "Gemini 4 Neon (XHigh)");
    assert.deepEqual(models["gemini-4-neon-xhigh"].variants, { xhigh: {} });

    assert.equal(models["claude-opus-5-5"].api.npm, "@ai-sdk/anthropic");
    assert.equal(models["claude-opus-5-5"].api.url, `${remoteRoot}/v1`);
    assert.ok(models["claude-opus-5-5-low"]);
    assert.ok(models["claude-opus-5-5-high"]);

    assert.equal(models["gpt-oss-120b"].api.npm, "@ai-sdk/openai-compatible");
    assert.equal(models["gpt-oss-120b"].api.url, `${remoteRoot}/v1`);
    assert.ok(models["custom-future-argon"]);

    assert.equal(isXhighGeminiModel(remoteRoot, "gemini-4-neon"), true);
    assert.equal(isXhighGeminiModel(remoteRoot, "claude-opus-5-5"), false);

    const qgMap = getModelQuotaGroupMap(remoteRoot);
    assert.equal(qgMap.get("gemini-4-neon"), "gemini");
    assert.equal(qgMap.get("gemini-4-neon-xhigh"), "gemini");
    assert.equal(qgMap.get("claude-opus-5-5-low"), "3p");
    assert.equal(qgMap.get("custom-future-argon"), "gemini-argon-wtu");

    // Switching to fold_effort_variants = true hides synthetic suffixed models
    const folded = getDiscoveredModels(remoteRoot, { foldEffortVariants: true });
    assert.ok(folded["gemini-4-neon"]);
    assert.equal(folded["gemini-4-neon-xhigh"], undefined);
    assert.equal(folded["claude-opus-5-5-low"], undefined);
  });

  it("falls back to public /v1/models and /v1beta/models when /api/models fails", async () => {
    const fetchImpl = async (url) => {
      if (url.endsWith("/api/models")) {
        return makeJsonResponse({ error: "admin_login_required" }, 401);
      }
      if (url.endsWith("/v1/models")) {
        return makeJsonResponse({
          data: [
            {
              id: "gemini-4-pro",
              context_length: 1000000,
              max_completion_tokens: 65536,
              input_modalities: ["text", "image", "pdf"],
              supported_reasoning_levels: ["low", "high"],
              default_reasoning_level: "low",
            },
          ],
        });
      }
      if (url.endsWith("/v1beta/models")) {
        return makeJsonResponse({
          models: [
            {
              name: "models/gemini-4-pro",
              displayName: "Gemini 4 Pro",
              inputTokenLimit: 1000000,
              outputTokenLimit: 65536,
            },
          ],
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    };

    const models = await reconcileModels(
      {},
      { auth: { key: "sk-pub", metadata: { baseUrl: "http://127.0.0.1:8017" } } },
      { fetchImpl },
    );

    assert.ok(models["gemini-4-pro"]);
    assert.ok(models["gemini-4-pro-low"]);
    assert.ok(models["gemini-4-pro-high"]);
    assert.equal(models["gemini-4-pro"].capabilities.input.pdf, true);
    assert.equal(models["gemini-4-pro"].capabilities.input.image, true);
  });

  it("sets fellBack symbol when all discovery endpoints fail", async () => {
    const fetchImpl = async () => {
      throw new Error("ECONNREFUSED");
    };
    const prev = { "gemini-4-neon": { id: "gemini-4-neon" } };
    const result = await reconcileModels(
      { models: prev },
      { auth: { key: "sk-pub" } },
      { fetchImpl },
    );
    assert.equal(result[Symbol.for("magpie.fellBack")], true);
    assert.ok(result["gemini-4-neon"]);
  });

  it("preserves real suffixed entries without fabricating base models and only folds synthetic variants", () => {
    const raw = new Map([
      [
        "gemini-fixture",
        {
          id: "gemini-fixture",
          provider: "MODEL_PROVIDER_GOOGLE",
          quota_group: "gemini",
          thinking_levels: ["low", "high"],
        },
      ],
      [
        "gemini-fixture-low",
        {
          id: "gemini-fixture-low",
          name: "Standalone Alias Low",
          provider: "MODEL_PROVIDER_GOOGLE",
          quota_group: "3p",
        },
      ],
      [
        "example-low",
        {
          id: "example-low",
          provider: "MODEL_PROVIDER_OPENAI",
          quota_group: "3p",
        },
      ],
    ]);

    const unfolded = buildModelsFromRawEntries(raw, DEFAULT_BASE_URL, { foldEffortVariants: false });
    assert.ok(unfolded.models["gemini-fixture"]);
    assert.equal(unfolded.models["gemini-fixture-low"].name, "Standalone Alias Low");
    assert.equal(unfolded.modelQuotaGroupMap.get("gemini-fixture-low"), "3p");
    assert.ok(unfolded.models["gemini-fixture-high"]);
    assert.ok(unfolded.models["example-low"]);
    assert.equal(unfolded.models["example"], undefined);

    const folded = buildModelsFromRawEntries(raw, DEFAULT_BASE_URL, { foldEffortVariants: true });
    assert.ok(folded.models["gemini-fixture"]);
    assert.deepEqual(Object.keys(folded.models["gemini-fixture"].variants), ["low", "high"]);
    assert.ok(folded.models["gemini-fixture-low"]);
    assert.ok(folded.models["example-low"]);
    assert.equal(folded.models["gemini-fixture-high"], undefined);
    assert.equal(folded.models["example"], undefined);
    assert.deepEqual(folded.modelMetadataMap.get("gemini-fixture").syntheticVariantIds, [
      "gemini-fixture-high",
    ]);
  });

  it("treats an authoritative empty admin catalog as success and clears old models", async () => {
    const root = "https://catalog.example.invalid";
    const ctx = { auth: { key: "fixture-public-key", metadata: { baseUrl: root } } };
    let items = [{ id: "gemini-fixture", thinking_levels: ["high", "xhigh"] }];
    const paths = [];
    const deps = {
      fetchImpl: async (url) => {
        paths.push(new URL(url).pathname);
        return makeJsonResponse({ models: items });
      },
    };
    assert.ok((await reconcileModels({}, ctx, deps))["gemini-fixture"]);
    items = [];
    const result = await reconcileModels({}, ctx, deps);
    assert.deepEqual(Object.keys(result), []);
    assert.equal(result[Symbol.for("magpie.fellBack")], undefined);
    assert.deepEqual(paths, ["/api/models", "/api/settings", "/api/models"]);
  });

  it("falls back to paginated /v1beta/models with camelCase fields and rejects duplicate pageToken cycles", async () => {
    const root = "https://beta-page.example.invalid";
    const requestedUrls = [];
    const fetchImpl = async (url) => {
      requestedUrls.push(url);
      const u = new URL(url);
      if (u.pathname === "/api/models") {
        return makeJsonResponse({ error: "admin_login_required" }, 401);
      }
      if (u.pathname === "/v1/models") {
        return makeJsonResponse({ error: "unavailable" }, 503);
      }
      if (u.pathname === "/v1beta/models") {
        assert.equal(u.searchParams.get("pageSize"), "1000");
        const token = u.searchParams.get("pageToken");
        if (!token) {
          return makeJsonResponse({
            models: [
              {
                name: "models/gemini-fixture",
                baseModelId: "gemini-fixture",
                displayName: "Fixture Display",
                thinking: true,
                thinkingLevels: ["high", "xhigh"],
                defaultThinkingLevel: "high",
                inputTokenLimit: 8192,
                outputTokenLimit: 2048,
              },
            ],
            nextPageToken: "1",
          });
        }
        assert.equal(token, "1");
        return makeJsonResponse({
          models: [
            {
              name: "models/gemini-second",
              baseModelId: "gemini-second",
              displayName: "Second Display",
              inputTokenLimit: 4096,
              outputTokenLimit: 1024,
            },
          ],
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    };

    const models = await reconcileModels(
      {},
      { auth: { key: "sk-pub", metadata: { baseUrl: root } } },
      { fetchImpl, foldEffortVariants: true },
    );
    assert.ok(models["gemini-fixture"]);
    assert.equal(models["gemini-fixture"].name, "Fixture Display");
    assert.deepEqual(models["gemini-fixture"].limit, { context: 8192, output: 2048 });
    assert.deepEqual(Object.keys(models["gemini-fixture"].variants), ["high", "xhigh"]);
    assert.equal(isXhighGeminiModel(root, "gemini-fixture"), true);
    assert.ok(models["gemini-second"]);
    assert.ok(requestedUrls.some((u) => u.includes("pageToken=1")));

    // Duplicate nextPageToken cycle fails discovery instead of returning partial catalog
    clearModelCache();
    const cycleFetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === "/v1beta/models") {
        return makeJsonResponse({
          models: [{ name: "models/gemini-partial", baseModelId: "gemini-partial" }],
          nextPageToken: "loop-token",
        });
      }
      return makeJsonResponse({ error: "fail" }, 503);
    };
    const fellBack = await reconcileModels(
      {},
      { auth: { key: "sk-pub", metadata: { baseUrl: root } } },
      { fetchImpl: cycleFetch },
    );
    assert.equal(fellBack[Symbol.for("magpie.fellBack")], true);
    assert.equal(fellBack["gemini-partial"], undefined);
  });

  it("prefers explicit provider field over model id prefix", () => {
    const raw = new Map([
      [
        "claude-fixture",
        {
          id: "claude-fixture",
          provider: "MODEL_PROVIDER_GOOGLE",
          thinking_levels: ["high", "xhigh"],
        },
      ],
    ]);
    const built = buildModelsFromRawEntries(raw, DEFAULT_BASE_URL, { foldEffortVariants: true });
    assert.equal(built.models["claude-fixture"].api.npm, "@ai-sdk/google");
    assert.equal(built.models["claude-fixture"].api.url, `${DEFAULT_BASE_URL}/v1beta`);
    assert.equal(built.xhighGeminiModels.has("claude-fixture"), true);
  });

  it("falls back with fellBack symbol when admin fails and public fallback returns empty, and matches date-suffixed xhigh models only", async () => {
    const root = "https://empty-public.example.invalid";
    const configured = { "custom-configured": { id: "custom-configured" } };
    const fellBack = await reconcileModels(
      { models: configured },
      { auth: { key: "sk-pub", metadata: { baseUrl: root } } },
      {
        fetchImpl: async (url) => {
          const p = new URL(url).pathname;
          if (p === "/api/models") return makeJsonResponse({ error: "unavailable" }, 500);
          if (p === "/v1/models") return makeJsonResponse({ object: "list", data: [] }, 200);
          if (p === "/v1beta/models") return makeJsonResponse({ error: "unavailable" }, 503);
          throw new Error(`Unexpected ${url}`);
        },
      },
    );
    assert.equal(fellBack[Symbol.for("magpie.fellBack")], true);
    assert.ok(fellBack["custom-configured"]);

    // Date-suffixed @YYYYMMDD resolves xhigh from base model; arbitrary @suffix does not
    clearModelCache();
    await reconcileModels(
      {},
      { auth: { key: "sk-pub", metadata: { baseUrl: root } } },
      {
        fetchImpl: async (url) => {
          if (new URL(url).pathname === "/api/models") {
            return makeJsonResponse({
              models: [
                {
                  id: "gemini-fixture",
                  provider: "MODEL_PROVIDER_GOOGLE",
                  thinking_levels: ["high", "xhigh"],
                },
              ],
            });
          }
          throw new Error(`Unexpected ${url}`);
        },
      },
    );
    assert.equal(isXhighGeminiModel(root, "gemini-fixture@20261001"), true);
    assert.equal(isXhighGeminiModel(root, "gemini-fixture@unknown"), false);
  });

  it("handles MODEL_MAPPING aliases without synthesizing suffixes, locks fixed-effort variants, filters internal models, and sets image/limit=0", async () => {
    const root = "https://settings-models.example.invalid";
    const models = await reconcileModels(
      {},
      {
        auth: {
          key: "sk-pub",
          metadata: { baseUrl: root, adminUsername: "admin", adminPassword: "pw" },
        },
      },
      {
        fetchImpl: async (url) => {
          const p = new URL(url).pathname;
          if (p === "/api/session") {
            return makeJsonResponse({}, 200, { "set-cookie": "antigravity_admin=tok-s; Path=/api" });
          }
          if (p === "/api/settings") {
            return makeJsonResponse({
              MODEL_MAPPING:
                "alias-base:gemini-4-carbon, alias-fixed:gemini-4-carbon-high, alias-base:should-not-win, ns:colon:claude-opus-5-5",
            });
          }
          if (p === "/api/models") {
            return makeJsonResponse({
              models: [
                {
                  id: "gemini-4-carbon",
                  provider: "MODEL_PROVIDER_GOOGLE",
                  quota_group: "gemini",
                  thinking_levels: ["low", "medium", "high"],
                  capabilities: { thinking: true },
                },
                {
                  id: "alias-base",
                  provider: "MODEL_PROVIDER_GOOGLE",
                  quota_group: "gemini",
                  thinking_levels: ["low", "medium", "high"],
                  capabilities: { thinking: true },
                },
                {
                  id: "alias-fixed",
                  provider: "MODEL_PROVIDER_GOOGLE",
                  quota_group: "gemini",
                  thinking_levels: ["low", "medium", "high"],
                  capabilities: { thinking: true },
                },
                {
                  id: "gpt-oss-120b-medium",
                  provider: "MODEL_PROVIDER_OPENAI",
                  quota_group: "3p",
                  thinking_levels: [],
                  capabilities: { thinking: true },
                },
                {
                  id: "proactive-observer-v10",
                  capabilities: { transcription: true },
                },
                {
                  id: "tab_flash_lite_preview",
                  capabilities: { completion: true },
                },
                {
                  id: "gemini-3-image",
                  provider: "MODEL_PROVIDER_GOOGLE",
                  capabilities: { image_generation: true, thinking: true },
                },
              ],
            });
          }
          throw new Error(`Unexpected ${url}`);
        },
        foldEffortVariants: false,
      },
    );

    // Non-chat internal models dropped
    assert.equal(models["proactive-observer-v10"], undefined);
    assert.equal(models["tab_flash_lite_preview"], undefined);

    // Alias to base model does NOT synthesize -low/-medium/-high, keeps base variants
    assert.ok(models["alias-base"]);
    assert.equal(models["alias-base-low"], undefined);
    assert.equal(models["alias-base-high"], undefined);
    assert.deepEqual(Object.keys(models["alias-base"].variants), ["low", "medium", "high"]);

    // Alias to fixed-suffix target locks variants to { high: {} } and synthesizes nothing
    assert.ok(models["alias-fixed"]);
    assert.equal(models["alias-fixed-low"], undefined);
    assert.deepEqual(models["alias-fixed"].variants, { high: {} });

    // Upstream fixed-suffix reasoning model locks variants to { medium: {} } (prevents borrowedEfforts)
    assert.deepEqual(models["gpt-oss-120b-medium"].variants, { medium: {} });
    assert.equal(models["gpt-oss-120b-medium"].capabilities.reasoning, true);

    // Image model output: ["image"], toolcall: false, reasoning: false
    assert.equal(models["gemini-3-image"].capabilities.output.image, true);
    assert.equal(models["gemini-3-image"].capabilities.output.text, false);
    assert.equal(models["gemini-3-image"].capabilities.toolcall, false);
    assert.equal(models["gemini-3-image"].capabilities.reasoning, false);

    // Missing limits default to 0 (no fabricated 128000 / 65536)
    assert.deepEqual(models["gemini-4-carbon"].limit, { context: 0, output: 0 });
  });

  it("isolates model cache by auth scope, refreshes after TTL, treats valid public empty as {}, and throws expired on public auth rejection", async () => {
    const root = "https://scope-empty.example.invalid";
    let now = 1_700_000_000_000;
    let modelVer = 1;

    // 1. Scope isolation & TTL expiry in ensureModelsDiscovered
    const { ensureModelsDiscovered } = await import("../lib/models.mjs");
    const fetchScope = async (url, init) => {
      const p = new URL(url).pathname;
      const hdrs = new Headers(init?.headers);
      if (p === "/api/models") return makeJsonResponse({ error: "admin_login_required" }, 401);
      if (p === "/v1/models") {
        if (hdrs.get("authorization") === "Bearer sk-a") {
          return makeJsonResponse({ data: [{ id: `model-a-v${modelVer}` }] });
        }
        if (hdrs.get("authorization") === "Bearer sk-b") {
          return makeJsonResponse({ data: [{ id: "model-b" }] });
        }
      }
      if (p === "/v1beta/models") return makeJsonResponse({ models: [] });
      throw new Error(`Unexpected ${url}`);
    };

    const a1 = await ensureModelsDiscovered(
      { baseUrl: root, apiKey: "sk-a" },
      undefined,
      { fetchImpl: fetchScope, nowFn: () => now },
    );
    const b1 = await ensureModelsDiscovered(
      { baseUrl: root, apiKey: "sk-b" },
      undefined,
      { fetchImpl: fetchScope, nowFn: () => now },
    );
    assert.ok(a1["model-a-v1"]);
    assert.equal(a1["model-b"], undefined);
    assert.ok(b1["model-b"]);
    assert.equal(b1["model-a-v1"], undefined);

    // After 60s TTL, ensureModelsDiscovered re-fetches
    modelVer = 2;
    now += 61_000;
    const a2 = await ensureModelsDiscovered(
      { baseUrl: root, apiKey: "sk-a" },
      undefined,
      { fetchImpl: fetchScope, nowFn: () => now },
    );
    assert.ok(a2["model-a-v2"]);

    // 2. Valid public empty catalog (both 200 empty) clears old models without fellBack
    clearModelCache();
    let emptyPublic = false;
    const emptyFetch = async (url) => {
      const p = new URL(url).pathname;
      if (p === "/api/models") return makeJsonResponse({ error: "admin_login_required" }, 401);
      if (p === "/v1/models") {
        return makeJsonResponse({ data: emptyPublic ? [] : [{ id: "old-public-model" }] });
      }
      if (p === "/v1beta/models") return makeJsonResponse({ models: [] });
      throw new Error(`Unexpected ${url}`);
    };
    assert.ok(
      (await reconcileModels({}, { auth: { key: "sk-empty", metadata: { baseUrl: root } } }, { fetchImpl: emptyFetch }))[
        "old-public-model"
      ],
    );
    emptyPublic = true;
    const cleared = await reconcileModels(
      {},
      { auth: { key: "sk-empty", metadata: { baseUrl: root } } },
      { fetchImpl: emptyFetch },
    );
    assert.deepEqual(Object.keys(cleared), []);
    assert.equal(cleared[Symbol.for("magpie.fellBack")], undefined);

    // 3. Public 401/403/Gemini 400 API_KEY_INVALID throws err.signIn === "expired", while admin 401 alone does NOT
    clearModelCache();
    await assert.rejects(
      () =>
        reconcileModels(
          {},
          { auth: { key: "sk-bad", metadata: { baseUrl: root } } },
          {
            fetchImpl: async (url) => {
              const p = new URL(url).pathname;
              if (p === "/api/models") return makeJsonResponse({ error: "admin_login_required" }, 401);
              if (p === "/v1/models") return makeJsonResponse({ error: { code: "invalid_api_key" } }, 401);
              if (p === "/v1beta/models") {
                return makeJsonResponse(
                  { error: { code: 400, details: [{ reason: "API_KEY_INVALID" }] } },
                  400,
                );
              }
              throw new Error(`Unexpected ${url}`);
            },
          },
        ),
      (err) => err?.signIn === "expired",
    );

    // Admin 401 alone with valid public endpoint succeeds normally
    clearModelCache();
    const okFromPublic = await reconcileModels(
      {},
      { auth: { key: "sk-good", metadata: { baseUrl: root, adminPassword: "wrong" } } },
      {
        fetchImpl: async (url) => {
          const p = new URL(url).pathname;
          if (p === "/api/session") return makeJsonResponse({ error: { code: "invalid_credentials" } }, 401);
          if (p === "/v1/models") return makeJsonResponse({ data: [{ id: "public-ok-model" }] });
          if (p === "/v1beta/models") return makeJsonResponse({ models: [] });
          throw new Error(`Unexpected ${url}`);
        },
      },
    );
    assert.ok(okFromPublic["public-ok-model"]);
  });
});

describe("quota.mjs", () => {
  beforeEach(() => {
    clearAdminSessionCache();
    clearModelCache();
    clearQuotaCache();
  });

  it("includes cooling accounts as schedulable, applies group cooldown as 0 effective, and isolates healthy pools", () => {
    const nowMs = Date.parse("2026-11-22T15:00:00Z");
    const accounts = [
      {
        id: "alice@example.com",
        label: "Account A",
        state: "cooling",
        tier: "g1-pro-tier",
        cooldown: { "3p": "2026-11-22T18:00:00Z", "gemini-4-neon": "2026-11-22T15:10:00Z" },
        quota: [
          { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.9, reset_time: "2026-11-29T06:00:00Z" },
          { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.8, reset_time: "2026-11-22T17:00:00Z" },
          { bucket_id: "3p-weekly", window: "weekly", remaining_fraction: 0.7, reset_time: "2026-11-29T06:00:00Z" },
          { bucket_id: "3p-5h", window: "5h", remaining_fraction: 0.5, reset_time: "2026-11-22T16:30:00Z" },
        ],
        quota_at: "2026-11-22T14:55:00Z",
      },
      {
        id: "bob@example.com",
        label: "Account B",
        state: "disabled",
        tier: "g1-ultra-tier",
        quota: [
          { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.1, reset_time: "2026-11-29T06:00:00Z" },
          { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.1, reset_time: "2026-11-22T17:00:00Z" },
        ],
        quota_at: "2026-11-22T14:55:00Z",
      },
    ];

    const discoveredModels = {
      "gemini-4-neon": { id: "gemini-4-neon", name: "Gemini 4 Neon", family: "Gemini" },
      "gemini-4-neon-high": { id: "gemini-4-neon-high", name: "Gemini 4 Neon (High)", family: "Gemini" },
      "claude-opus-5-5": { id: "claude-opus-5-5", name: "Claude Opus 5.5", family: "Claude" },
    };
    const modelQuotaGroupMap = new Map([
      ["gemini-4-neon", "gemini"],
      ["gemini-4-neon-high", "gemini"],
      ["claude-opus-5-5", "3p"],
    ]);

    const usage = computeAgy2ApiUsage(accounts, {
      discoveredModels,
      modelQuotaGroupMap,
      nowMs,
    });

    assert.equal(usage.plan, "PRO ×1");

    // Individual model ID cooldown "gemini-4-neon" must NOT create a separate pool!
    const poolNames = new Set(usage.windows.filter((w) => w.pool).map((w) => w.pool));
    assert.deepEqual([...poolNames], ["Gemini", "Claude & GPT"]);

    // Model-level cooldown "gemini-4-neon" affects only gemini-4-neon (100% used, resets at 15:10), NOT sibling gemini-4-neon-high (20% used)
    const geminiWin = usage.windows.find((w) => !w.aside && w.model === "gemini-4-neon");
    assert.equal(geminiWin.used, 100);
    assert.equal(geminiWin.resetsAt, "2026-11-22T15:10:00.000Z");
    assert.equal(geminiWin.pool, "Gemini");

    // Sibling / expanded effort model without model-level cooldown stays at pool 20% used
    const geminiHighWin = usage.windows.find((w) => !w.aside && w.model === "gemini-4-neon-high");
    assert.equal(geminiHighWin.used, 20);

    // 3p pool has active cooldown -> 0% effective remaining -> 100% used, reset uses cooldown 18:00 since 5h bucket reset 16:30 is earlier
    const claudeWin = usage.windows.find((w) => !w.aside && w.model === "claude-opus-5-5");
    assert.equal(claudeWin.used, 100);
    assert.equal(claudeWin.resetsAt, "2026-11-22T18:00:00.000Z");

    // Per-account detail windows never have >1 " · " in display
    for (const w of usage.windows) {
      if (w.display) {
        const count = (w.display.match(/ · /g) || []).length;
        assert.ok(count <= 1, `Too many ' · ' in display: ${w.display}`);
      }
    }
  });

  it("maps Ultra / Ultra-lite Argon to Gemini buckets and cooldowns when Argon buckets are absent", () => {
    const nowMs = Date.parse("2026-11-22T15:00:00Z");
    const ultraAcc = {
      id: "ultra@example.com",
      state: "ready",
      tier: "g1-ultra-lite-tier",
      cooldown: { gemini: "2026-11-22T16:00:00Z" },
      quota: [
        { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.7, reset_time: "2026-11-22T17:00:00Z" },
        { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.9, reset_time: "2026-11-29T06:00:00Z" },
      ],
      quota_at: "2026-11-22T14:55:00Z",
    };

    const q = extractAccountGroupQuota(ultraAcc, "gemini-argon-wtu", nowMs);
    assert.equal(q.known, true);
    assert.equal(q.pool, "gemini");
    assert.equal(q.inCooldown, true);
    assert.equal(q.effectiveRem, 0);
    assert.equal(q.h5, 70);
    assert.equal(q.weekly, 90);

    // The account itself has no Argon pool: asking for that pool directly finds nothing
    assert.equal(resolveAccountPool(ultraAcc, "gemini-argon-wtu"), "gemini");
    assert.equal(extractAccountPoolQuota(ultraAcc, "gemini-argon-wtu", nowMs).known, false);

    // An account with its own Argon bucket keeps the group on that pool
    const proAcc = {
      ...ultraAcc,
      id: "pro@example.com",
      cooldown: undefined,
      quota: [
        ...ultraAcc.quota,
        { bucket_id: "gemini-argon-wtu-weekly", window: "weekly", remaining_fraction: 0.4, reset_time: "2026-11-29T08:00:00Z" },
      ],
    };
    assert.equal(resolveAccountPool(proAcc, "gemini-argon-wtu"), "gemini-argon-wtu");
    const proQ = extractAccountGroupQuota(proAcc, "gemini-argon-wtu", nowMs);
    assert.equal(proQ.pool, "gemini-argon-wtu");
    assert.equal(proQ.weekly, 40);
    assert.equal(proQ.h5, null);

    // Groups without a fallback rule stay on their own pool even when the account lacks it
    assert.equal(resolveAccountPool(ultraAcc, "3p"), "3p");
    assert.equal(extractAccountGroupQuota(ultraAcc, "3p", nowMs).known, false);
  });

  it("shows only pools accounts actually have: no Argon pool, row segment or model pool when Argon is billed to Gemini", () => {
    const nowMs = Date.parse("2026-11-24T03:00:00Z");
    const gem = (h5, weekly) => [
      { bucket_id: "gemini-5h", window: "5h", remaining_fraction: h5, reset_time: "2026-11-24T06:00:00Z" },
      { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: weekly, reset_time: "2026-12-01T03:00:00Z" },
    ];
    const tp = (weekly) => [
      { bucket_id: "3p-5h", window: "5h", remaining_fraction: 1, reset_time: "2026-11-24T06:00:00Z" },
      { bucket_id: "3p-weekly", window: "weekly", remaining_fraction: weekly, reset_time: "2026-11-29T06:00:00Z" },
    ];
    const argon = (weekly) => [
      { bucket_id: "gemini-argon-wtu-weekly", window: "weekly", remaining_fraction: weekly, reset_time: "2026-11-29T08:00:00Z" },
    ];
    const options = {
      nowMs,
      discoveredModels: {
        "gemini-4-neon": { id: "gemini-4-neon" },
        "gemini-4-argon": { id: "gemini-4-argon" },
        "claude-opus-5-5": { id: "claude-opus-5-5" },
      },
      modelQuotaGroupMap: new Map([
        ["gemini-4-neon", "gemini"],
        ["gemini-4-argon", "gemini-argon-wtu"],
        ["claude-opus-5-5", "3p"],
      ]),
    };
    const poolRows = (usage) =>
      usage.windows.filter((w) => w.pool && !w.model).map((w) => `${w.pool} ${w.name} ${w.used}`);
    const row = (usage, label) => usage.windows.find((w) => w.name.startsWith(`${label} ·`)).display;
    const modelWin = (usage, id) => usage.windows.find((w) => !w.aside && w.model === id);

    // 1. Every account bills Argon to its Gemini pool (what /api/accounts returns today)
    const merged = computeAgy2ApiUsage(
      [
        { id: "ultra@example.com", label: "Ultra", state: "ready", tier: "g1-ultra-tier", quota: [...gem(0.8, 0.9), ...tp(1)] },
        { id: "pro@example.com", label: "Pro", state: "ready", tier: "g1-pro-tier", quota: [...gem(1, 0.6), ...tp(0.5)] },
      ],
      options,
    );
    assert.deepEqual(poolRows(merged), [
      "Gemini 5 hours 11",
      "Gemini 7 days 23",
      "Claude & GPT 5 hours 0",
      "Claude & GPT 7 days 21",
    ]);
    assert.equal(merged.windows.some((w) => w.pool === "Gemini 4 Argon"), false);
    assert.equal(row(merged, "Ultra"), "Gemini 80%/90% · Claude 100%/100%");
    assert.equal(row(merged, "Pro"), "Gemini 100%/60% · Claude 100%/50%");
    // The Argon model is still routed on the Gemini quota and is filed under the Gemini pool
    assert.equal(modelWin(merged, "gemini-4-argon").pool, "Gemini");
    assert.equal(modelWin(merged, "gemini-4-argon").used, modelWin(merged, "gemini-4-neon").used);
    assert.equal(modelWin(merged, "gemini-4-argon").resetsAt, modelWin(merged, "gemini-4-neon").resetsAt);

    // 2. Mixed: one account has its own Argon bucket, the other bills Argon to Gemini
    const mixed = computeAgy2ApiUsage(
      [
        { id: "ultra@example.com", label: "Ultra", state: "ready", tier: "g1-ultra-tier", quota: [...gem(0.8, 0.9), ...tp(1)] },
        { id: "pro@example.com", label: "Pro", state: "ready", tier: "g1-pro-tier", quota: [...gem(1, 0.6), ...tp(0.5), ...argon(0.2)] },
      ],
      options,
    );
    // The Argon pool is the Pro account's bucket alone: weekly only, no Gemini numbers mixed in
    assert.deepEqual(poolRows(mixed), [
      "Gemini 5 hours 11",
      "Gemini 7 days 23",
      "Claude & GPT 5 hours 0",
      "Claude & GPT 7 days 21",
      "Gemini 4 Argon 7 days 80",
    ]);
    assert.equal(row(mixed, "Ultra"), "Gemini 80%/90% · Claude 100%/100%");
    assert.equal(row(mixed, "Pro"), "Gemini 100%/60% · Claude 100%/50%  Argon 20%");
    // Routing still weighs both accounts: Ultra's Gemini 80% (x2.0) and Pro's Argon 20% (x1.5)
    assert.equal(modelWin(mixed, "gemini-4-argon").pool, "Gemini 4 Argon");
    assert.equal(modelWin(mixed, "gemini-4-argon").used, 46);
    assert.equal(modelWin(mixed, "gemini-4-neon").pool, "Gemini");

    // 3. Buckets left on a disabled account do not bring a pool back
    const stale = computeAgy2ApiUsage(
      [
        { id: "pro@example.com", label: "Pro", state: "ready", tier: "g1-pro-tier", quota: [...gem(1, 0.6), ...tp(0.5)] },
        { id: "off@example.com", label: "Off", state: "disabled", tier: "g1-pro-tier", quota: [...gem(1, 1), ...argon(0.1)] },
      ],
      options,
    );
    assert.equal(stale.windows.some((w) => w.pool === "Gemini 4 Argon"), false);
    assert.equal(modelWin(stale, "gemini-4-argon").pool, "Gemini");
    assert.equal(row(stale, "Off"), "已禁用");

    // 4. A leftover future cooldown keyed by the group does not create a pool or block the model:
    //    the account bills Argon to Gemini, so only its Gemini cooldown counts
    const leftover = computeAgy2ApiUsage(
      [
        {
          id: "pro@example.com",
          label: "Pro",
          state: "cooling",
          tier: "g1-pro-tier",
          cooldown: { "gemini-argon-wtu": "2026-11-29T08:00:00Z" },
          quota: [...gem(1, 0.6), ...tp(0.5)],
        },
      ],
      options,
    );
    assert.equal(leftover.windows.some((w) => w.pool === "Gemini 4 Argon"), false);
    assert.equal(modelWin(leftover, "gemini-4-argon").used, 40);
  });

  it("deduplicates shared[group] and matching family weekly buckets via Union-Find", () => {
    const nowMs = Date.parse("2026-11-22T15:00:00Z");
    const accounts = [
      // Shared pair for gemini: Alice (FREE, 1.0) and Bob (ULTRA, 2.0) -> counted ONCE with weight 2.0, min rem = 50%
      {
        id: "alice@example.com",
        label: "Alice",
        state: "ready",
        tier: "free-tier",
        shared: { gemini: ["bob@example.com"] },
        quota: [
          { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.6, reset_time: "2026-11-22T18:00:00Z" },
          { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.8, reset_time: "2026-11-29T06:00:00Z" },
        ],
        quota_at: "2026-11-22T14:55:00Z",
      },
      {
        id: "bob@example.com",
        label: "Bob",
        state: "ready",
        tier: "Google AI Ultra",
        quota: [
          { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.5, reset_time: "2026-11-22T18:00:00Z" },
          { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.8, reset_time: "2026-11-29T06:00:00Z" },
        ],
        quota_at: "2026-11-22T14:55:00Z",
      },
      // Family pair: Carol & Dave with started weekly < 1 and reset within 1s -> counted ONCE (weight 1.5, rem 100%)
      {
        id: "carol@example.com",
        label: "Carol",
        state: "ready",
        tier: "g1-pro-tier",
        family: ["dave@example.com"],
        quota: [
          { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 1.0, reset_time: "2026-11-22T18:00:00Z" },
          { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.9, reset_time: "2026-11-29T06:00:00Z" },
        ],
        quota_at: "2026-11-22T14:55:00Z",
      },
      {
        id: "dave@example.com",
        label: "Dave",
        state: "ready",
        tier: "free-tier",
        family: ["carol@example.com"],
        quota: [
          { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 1.0, reset_time: "2026-11-22T18:00:00Z" },
          { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.9, reset_time: "2026-11-29T06:00:01Z" },
        ],
        quota_at: "2026-11-22T14:55:00Z",
      },
      // Erin is in Carol's family list, but her weekly is 1.0 (not started < 1) -> NOT deduped! Weight 1.0, rem 100%
      {
        id: "erin@example.com",
        label: "Erin",
        state: "ready",
        tier: "free-tier",
        family: ["carol@example.com"],
        quota: [
          { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 1.0, reset_time: "2026-11-22T18:00:00Z" },
          { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 1.0, reset_time: "2026-11-29T06:00:00Z" },
        ],
        quota_at: "2026-11-22T14:55:00Z",
      },
    ];

    // Expected weighted remaining (shared 7d pool only; independent 5h takes max uncooled member):
    // Component 1 (Alice+Bob): weight=2.0, compWeekly=80, max(min(60,80), min(50,80))=60
    // Component 2 (Carol+Dave): weight=1.5, effectiveRem=90 (min(100,90))
    // Component 3 (Erin): weight=1.0, effectiveRem=100
    // Total = (2.0*60 + 1.5*90 + 1.0*100) / (2.0 + 1.5 + 1.0) = (120 + 135 + 100) / 4.5 = 355 / 4.5 = 78.89% -> 79% rem -> 21% used
    const usage = computeAgy2ApiUsage(accounts, {
      discoveredModels: {
        "gemini-4-neon": { id: "gemini-4-neon", name: "Gemini 4 Neon", family: "Gemini" },
      },
      modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
      nowMs,
    });

    const geminiWin = usage.windows.find((w) => !w.aside && w.model === "gemini-4-neon");
    assert.equal(geminiWin.used, 21);

    const aliceRow = usage.windows.find((w) => w.name === "Alice · FREE");
    assert.ok(aliceRow.display.includes("共享"));
    const carolRow = usage.windows.find((w) => w.name === "Carol · PRO");
    assert.ok(carolRow.display.includes("家庭"));

    for (const w of usage.windows) {
      if (w.display) {
        assert.ok((w.display.match(/ · /g) || []).length <= 1);
      }
    }
  });

  it("handles unknown quota without emitting non-aside 100% hold windows", () => {
    const accounts = [
      { id: "pending@example.com", state: "ready", tier: "free-tier", quota: [], quota_at: "" },
    ];
    const usage = computeAgy2ApiUsage(accounts, {
      discoveredModels: {
        "gemini-4-neon": { id: "gemini-4-neon", name: "Gemini 4 Neon", family: "Gemini" },
      },
      modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
    });

    // Must NOT emit non-aside windows with used: 100
    assert.equal(usage.windows.filter((w) => !w.aside).length, 0);
    // No account has reported a bucket, so there is no pool to name: one unknown row, no pool
    assert.equal(usage.windows.some((w) => w.pool), false);
    const unknownRows = usage.windows.filter((w) => w.name === "配额");
    assert.equal(unknownRows.length, 1);
    assert.equal(unknownRows[0].display, "未知");
    assert.equal(unknownRows[0].used, undefined);
    assert.equal(unknownRows[0].aside, true);
  });

  it("caches accounts, debounces refresh, and distinguishes stale cache from live error", async () => {
    let now = Date.parse("2026-11-22T15:00:00Z");
    let refreshCalls = 0;
    let accountCalls = 0;
    let shouldFailAccounts = false;

    const sampleAccounts = [
      {
        id: "alice@example.com",
        state: "ready",
        tier: "g1-pro-tier",
        quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.8 }],
        quota_at: "2026-11-22T14:59:00Z",
      },
    ];

    const fetchImpl = async (url) => {
      if (url.endsWith("/api/session")) {
        return new Response("{}", {
          status: 200,
          headers: { "set-cookie": "antigravity_admin=tok-q; Path=/api" },
        });
      }
      if (url.endsWith("/api/accounts/refresh")) {
        refreshCalls++;
        if (shouldFailAccounts) {
          return makeJsonResponse({ error: "internal error" }, 500);
        }
        return makeJsonResponse({ accounts: sampleAccounts, failed: {} });
      }
      if (url.endsWith("/api/accounts")) {
        accountCalls++;
        if (shouldFailAccounts) {
          return makeJsonResponse({ error: "internal error" }, 500);
        }
        return makeJsonResponse({ accounts: sampleAccounts });
      }
      throw new Error(`Unexpected URL ${url}`);
    };

    const opts = {
      baseUrl: DEFAULT_BASE_URL,
      adminUsername: "admin",
      adminPassword: "pw",
      cacheTtlSec: 10,
      refreshCooldownSec: 60,
      refreshOnUsage: true,
      discoveredModels: { "gemini-4-neon": { id: "gemini-4-neon", name: "Gemini 4 Neon", family: "Gemini" } },
      modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
      fetchImpl,
      nowFn: () => now,
    };

    // 1. First call uses POST /api/accounts/refresh directly without redundant GET
    const u1 = await getAgy2ApiUsage(opts);
    assert.equal(refreshCalls, 1);
    assert.equal(accountCalls, 0);
    assert.equal(u1.plan, "PRO ×1");

    // 2. Within 10s cache TTL -> served from cache without network
    now += 5_000;
    const u2 = await getAgy2ApiUsage(opts);
    assert.equal(refreshCalls, 1);
    assert.equal(accountCalls, 0);
    assert.equal(u2.plan, "PRO ×1");

    // 3. Past 10s cache TTL but within 60s refresh cooldown -> fetches accounts, skips refresh; fails -> stale warning!
    now += 10_000;
    shouldFailAccounts = true;
    const u3 = await getAgy2ApiUsage(opts);
    assert.equal(refreshCalls, 1);
    assert.equal(accountCalls, 1);
    assert.match(u3.plan, /旧缓存/);
    const statusRow = u3.windows.find((w) => w.name === "状态");
    assert.ok(statusRow);
    assert.equal(statusRow.aside, true);
    assert.match(statusRow.display, /刷新失败 · 显示旧缓存/);

    // 4. Fresh cache key with no prior cache -> returns { error }
    clearQuotaCache();
    const u4 = await getAgy2ApiUsage(opts);
    assert.ok(u4.error);
  });

  it("reports partial refresh failure count without leaking details, and marks POST non-2xx fallback as failed", async () => {
    let now = Date.parse("2026-11-22T15:00:00Z");
    const fetchPartial = async (url) => {
      if (url.endsWith("/api/accounts/refresh")) {
        return makeJsonResponse({
          accounts: [
            {
              id: "secret-user@example.com",
              state: "ready",
              tier: "g1-pro-tier",
              quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.8 }],
            },
          ],
          failed: {
            "secret-user@example.com": "secret upstream error text",
            "other-user@example.com": "another secret error",
          },
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    };

    const uPartial = await getAgy2ApiUsage({
      baseUrl: DEFAULT_BASE_URL,
      refreshOnUsage: true,
      cacheTtlSec: 10,
      showAccountDetails: false,
      discoveredModels: { "gemini-4-neon": { id: "gemini-4-neon", name: "Gemini 4 Neon", family: "Gemini" } },
      modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
      fetchImpl: fetchPartial,
      nowFn: () => now,
    });
    assert.match(uPartial.plan, /部分配额刷新失败（2 个账号）/);
    const statusRow = uPartial.windows.find((w) => w.name === "状态");
    assert.ok(statusRow);
    assert.match(statusRow.display, /部分配额刷新失败（2 个账号）/);
    assert.doesNotMatch(JSON.stringify(uPartial), /secret-user|other-user|secret upstream/);

    // Within TTL, cached snapshot keeps failure indicator instead of turning healthy
    now += 2000;
    const uPartialCached = await getAgy2ApiUsage({
      baseUrl: DEFAULT_BASE_URL,
      refreshOnUsage: true,
      cacheTtlSec: 10,
      showAccountDetails: false,
      discoveredModels: { "gemini-4-neon": { id: "gemini-4-neon", name: "Gemini 4 Neon", family: "Gemini" } },
      modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
      fetchImpl: fetchPartial,
      nowFn: () => now,
    });
    assert.match(uPartialCached.plan, /部分配额刷新失败（2 个账号）/);

    // POST 503 + GET 200 marks refresh failed (not fresh healthy data)
    clearQuotaCache();
    const fetchPostFail = async (url) => {
      if (url.endsWith("/api/accounts/refresh")) {
        return makeJsonResponse({ error: "unavailable" }, 503);
      }
      if (url.endsWith("/api/accounts")) {
        return makeJsonResponse({
          accounts: [
            {
              id: "alice@example.com",
              state: "ready",
              tier: "g1-pro-tier",
              quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.9 }],
            },
          ],
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    };
    const uPostFail = await getAgy2ApiUsage({
      baseUrl: DEFAULT_BASE_URL,
      refreshOnUsage: true,
      fetchImpl: fetchPostFail,
      nowFn: () => now,
    });
    assert.match(uPostFail.plan, /配额刷新失败/);
    assert.ok(uPostFail.windows.some((w) => w.name === "状态" && /配额刷新失败/.test(w.display)));
  });

  it("does not reuse private quota details after admin credentials change or auth rejection", async () => {
    const baseUrl = "https://quota-auth.example.invalid";
    let accountGets = 0;
    let correct = true;
    const fetchImpl = async (url, init) => {
      const pathname = new URL(url).pathname;
      if (pathname === "/api/session") {
        assert.equal(init.method, "POST");
        return correct
          ? makeJsonResponse({}, 200, { "set-cookie": "antigravity_admin=fixture-cookie; Path=/api" })
          : makeJsonResponse({ error: { code: "invalid_credentials", message: "fixture-private" } }, 401);
      }
      assert.equal(pathname, "/api/accounts");
      accountGets++;
      if (!new Headers(init.headers).has("cookie")) {
        return makeJsonResponse({ error: { code: "admin_login_required" } }, 401);
      }
      return makeJsonResponse({
        accounts: [{ id: "fixture@example.com", label: "Fixture Account", state: "ready" }],
      });
    };
    const opts = {
      baseUrl,
      fetchImpl,
      refreshOnUsage: false,
      nowFn: () => 1000000,
      showAccountDetails: true,
    };
    assert.match(
      JSON.stringify(await getAgy2ApiUsage({ ...opts, adminPassword: "fixture-current" })),
      /Fixture Account/,
    );
    correct = false;
    for (const adminPassword of ["", "fixture-new"]) {
      const usage = await getAgy2ApiUsage({ ...opts, adminPassword });
      assert.ok(usage.error);
      assert.doesNotMatch(JSON.stringify(usage), /Fixture Account|fixture-private/);
    }
    assert.equal(accountGets, 2);

    // Existing credential scope getting 401 on GET must NOT fall back to stale cache
    correct = true;
    let rejectAccounts = false;
    const fetchExpire = async (url) => {
      const pathname = new URL(url).pathname;
      if (pathname === "/api/session") {
        return rejectAccounts
          ? makeJsonResponse({ error: { code: "invalid_credentials" } }, 401)
          : makeJsonResponse({}, 200, { "set-cookie": "antigravity_admin=tok-exp; Path=/api" });
      }
      if (rejectAccounts) {
        return makeJsonResponse({ error: { code: "admin_login_required" } }, 401);
      }
      return makeJsonResponse({
        accounts: [{ id: "fixture@example.com", label: "Fixture Account", state: "ready" }],
      });
    };
    let now = 2000000;
    const okFirst = await getAgy2ApiUsage({
      baseUrl: "https://expire.example.invalid",
      adminPassword: "pw-1",
      cacheTtlSec: 5,
      refreshOnUsage: false,
      fetchImpl: fetchExpire,
      nowFn: () => now,
    });
    assert.match(JSON.stringify(okFirst), /Fixture Account/);

    now += 10000;
    rejectAccounts = true;
    const rejectedSecond = await getAgy2ApiUsage({
      baseUrl: "https://expire.example.invalid",
      adminPassword: "pw-1",
      cacheTtlSec: 5,
      refreshOnUsage: false,
      fetchImpl: fetchExpire,
      nowFn: () => now,
    });
    assert.ok(rejectedSecond.error);
    assert.doesNotMatch(JSON.stringify(rejectedSecond), /Fixture Account/);
  });

  it("handles fraction bounds, past reset renewal, rounding cap at 99, AI credits aside, and unmapped model omission", () => {
    const nowMs = Date.parse("2026-11-22T12:00:00Z");

    // 1. Out-of-range / NaN remaining_fraction -> unknown, NOT exhausted or /100
    for (const bad of [-0.1, 1.01, Number.NaN, undefined]) {
      const usage = computeAgy2ApiUsage(
        [
          {
            id: "a@example.com",
            state: "ready",
            quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: bad }],
          },
        ],
        {
          nowMs,
          showAccountDetails: false,
          discoveredModels: { "gemini-fixture": { id: "gemini-fixture" } },
          modelQuotaGroupMap: new Map([["gemini-fixture", "gemini"]]),
        },
      );
      assert.equal(usage.windows.filter((w) => !w.aside).length, 0);
    }

    // 2. Positive remaining 0.004 -> used capped at 99 (never 100)
    const tinyRem = computeAgy2ApiUsage(
      [
        {
          id: "a@example.com",
          state: "ready",
          quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.004 }],
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: { "gemini-fixture": { id: "gemini-fixture" } },
        modelQuotaGroupMap: new Map([["gemini-fixture", "gemini"]]),
      },
    );
    assert.equal(tinyRem.windows.find((w) => !w.aside).used, 99);

    // 3. Past reset_time -> renewed (remaining 1, no resetsAt)
    const renewed = computeAgy2ApiUsage(
      [
        {
          id: "a@example.com",
          state: "ready",
          quota: [
            {
              bucket_id: "gemini-5h",
              window: "5h",
              remaining_fraction: 0,
              reset_time: "2026-11-22T11:00:00Z",
            },
          ],
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: { "gemini-fixture": { id: "gemini-fixture" } },
        modelQuotaGroupMap: new Map([["gemini-fixture", "gemini"]]),
      },
    );
    const renewedWin = renewed.windows.find((w) => !w.aside);
    assert.equal(renewedWin.used, 0);
    assert.equal(renewedWin.resetsAt, undefined);

    // 4. AI credits enabled + sufficient balance + no future cooldown -> model window is aside: true (never non-aside used: 100)
    const futureReset = "2026-11-22T14:00:00.000Z";
    const creditsUsage = computeAgy2ApiUsage(
      [
        {
          id: "a@example.com",
          state: "ready",
          ai_credits: true,
          credit_balance: 500,
          credit_minimum: 100,
          quota: [
            {
              bucket_id: "gemini-5h",
              window: "5h",
              remaining_fraction: 0,
              reset_time: futureReset,
            },
          ],
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: {
          "gemini-fixture": { id: "gemini-fixture" },
          "unmapped-fixture": { id: "unmapped-fixture" },
        },
        modelQuotaGroupMap: new Map([["gemini-fixture", "gemini"]]),
      },
    );
    assert.equal(creditsUsage.windows.filter((w) => !w.aside).length, 0);
    assert.equal(creditsUsage.windows.some((w) => w.model === "unmapped-fixture"), false);
    const asideModelWin = creditsUsage.windows.find((w) => w.aside && w.model === "gemini-fixture");
    assert.equal(asideModelWin.used, 100);
  });

  it("does not merge Argon-mapped-to-Gemini account with peer having independent Argon buckets", () => {
    const nowMs = Date.parse("2026-11-22T15:00:00Z");
    const futureGeminiReset = "2026-11-29T06:00:00Z";
    const futureArgonReset = "2026-11-29T08:00:00Z";
    const accounts = [
      {
        id: "a@example.com",
        state: "ready",
        tier: "free-tier",
        shared: { gemini: ["b@example.com"] },
        quota: [
          { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.8, reset_time: futureGeminiReset },
        ],
      },
      {
        id: "b@example.com",
        state: "ready",
        tier: "free-tier",
        shared: { gemini: ["a@example.com"] },
        quota: [
          { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.8, reset_time: futureGeminiReset },
          { bucket_id: "gemini-argon-wtu-weekly", window: "weekly", remaining_fraction: 0.2, reset_time: futureArgonReset },
        ],
      },
    ];
    const usage = computeAgy2ApiUsage(accounts, {
      nowMs,
      showAccountDetails: false,
      discoveredModels: {
        "gemini-4-neon": { id: "gemini-4-neon" },
        "gemini-4-argon": { id: "gemini-4-argon" },
      },
      modelQuotaGroupMap: new Map([
        ["gemini-4-neon", "gemini"],
        ["gemini-4-argon", "gemini-argon-wtu"],
      ]),
    });

    assert.equal(usage.windows.find((w) => !w.aside && w.model === "gemini-4-neon").used, 20);
    assert.equal(usage.windows.find((w) => !w.aside && w.model === "gemini-4-argon").used, 50);
  });

  it("omits lookalike models without quota_group, respects Argon->Gemini cooldown & explicit shared isolation, and emits model cooldown on unknown quota", () => {
    const nowMs = Date.parse("2026-11-22T12:00:00Z");
    const pastReset = "2026-11-22T11:00:00Z";
    const futureGeminiCool = "2026-11-22T13:30:00.000Z";
    const futureArgonReset = "2026-11-29T08:00:00Z";
    const futureGemReset = "2026-11-29T06:00:00Z";

    // 1. Lookalike model name (gemini-lookalike) with NO quota_group metadata must NOT get bound to exhausted gemini pool
    const lookalikeUsage = computeAgy2ApiUsage(
      [
        {
          id: "a@example.com",
          state: "ready",
          quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0, reset_time: futureGemReset }],
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: {
          "gemini-real": { id: "gemini-real" },
          "gemini-lookalike": { id: "gemini-lookalike" },
        },
        modelQuotaGroupMap: new Map([["gemini-real", "gemini"]]),
      },
    );
    assert.equal(lookalikeUsage.windows.find((w) => w.model === "gemini-real")?.used, 100);
    assert.equal(lookalikeUsage.windows.some((w) => w.model === "gemini-lookalike"), false);

    // 2. Argon->Gemini mapped account with stale expired argon cooldown + active future gemini cooldown MUST be cooled (used: 100)
    // AND explicit shared["gemini-argon-wtu"] edge to an independent-Argon peer must NOT merge them!
    const argonUsage = computeAgy2ApiUsage(
      [
        {
          id: "mapped@example.com",
          state: "cooling",
          tier: "free-tier",
          shared: { "gemini-argon-wtu": ["indep@example.com"] },
          cooldown: {
            "gemini-argon-wtu": pastReset,
            gemini: futureGeminiCool,
          },
          quota: [{ bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.8, reset_time: futureGemReset }],
        },
        {
          id: "indep@example.com",
          state: "ready",
          tier: "free-tier",
          shared: { "gemini-argon-wtu": ["mapped@example.com"] },
          quota: [
            { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.8, reset_time: futureGemReset },
            { bucket_id: "gemini-argon-wtu-weekly", window: "weekly", remaining_fraction: 0.2, reset_time: futureArgonReset },
          ],
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: { "gemini-4-argon": { id: "gemini-4-argon" } },
        modelQuotaGroupMap: new Map([["gemini-4-argon", "gemini-argon-wtu"]]),
      },
    );
    // mapped (0 effective due to gemini cooldown) + indep (20 effective from argon bucket) => avg 10% rem => 90% used;
    // Also verify mapped account's own extractAccountGroupQuota picks future gemini cooldown!
    const mappedQ = extractAccountGroupQuota(
      {
        id: "mapped@example.com",
        cooldown: { "gemini-argon-wtu": pastReset, gemini: futureGeminiCool },
        quota: [{ bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.8, reset_time: futureGemReset }],
      },
      "gemini-argon-wtu",
      nowMs,
    );
    assert.equal(mappedQ.inCooldown, true);
    assert.equal(mappedQ.effectiveRem, 0);
    assert.equal(argonUsage.windows.find((w) => !w.aside && w.model === "gemini-4-argon")?.used, 90);

    // 3. Model with known quota_group + unknown bucket quota + future model cooldown -> emits used: 100 with resetsAt
    const unknownWithCool = computeAgy2ApiUsage(
      [
        {
          id: "cool-only@example.com",
          state: "cooling",
          quota: [],
          cooldown: { "gemini-fixture": futureGeminiCool },
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: { "gemini-fixture": { id: "gemini-fixture" } },
        modelQuotaGroupMap: new Map([["gemini-fixture", "gemini"]]),
      },
    );
    const coolWin = unknownWithCool.windows.find((w) => !w.aside && w.model === "gemini-fixture");
    assert.ok(coolWin);
    assert.equal(coolWin.used, 100);
    assert.equal(coolWin.resetsAt, futureGeminiCool);
  });

  it("persists refresh failure across TTL/cooldown skips, reports error when both POST & GET fail, and treats internal timeout as stale-eligible unlike caller abort", async () => {
    let now = Date.parse("2026-11-22T15:00:00Z");
    const calls = [];
    let getFails = false;
    let hangGetBody = false;

    const fetchImpl = async (url, init) => {
      const p = new URL(url).pathname;
      calls.push(p);
      if (p === "/api/accounts/refresh") {
        return makeJsonResponse({ error: "refresh unavailable" }, 503);
      }
      if (p === "/api/accounts") {
        if (hangGetBody) {
          return new Response(
            new ReadableStream({
              start(controller) {
                init.signal.addEventListener(
                  "abort",
                  () => controller.error(new DOMException("Aborted", "AbortError")),
                  { once: true },
                );
              },
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (getFails) {
          return makeJsonResponse({ error: "accounts unavailable" }, 503);
        }
        return makeJsonResponse({
          accounts: [
            {
              id: "alice@example.com",
              state: "ready",
              tier: "g1-pro-tier",
              quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.8 }],
            },
          ],
        });
      }
      throw new Error(`Unexpected ${url}`);
    };

    // 1. POST 503 + GET 503 with no prior cache -> error mentions refresh failure
    getFails = true;
    const bothFailed = await getAgy2ApiUsage({
      baseUrl: "https://refresh-persist.example.invalid",
      refreshOnUsage: true,
      fetchImpl,
      nowFn: () => now,
    });
    assert.ok(bothFailed.error);
    assert.match(bothFailed.error, /refresh/i);

    // 2. POST 503 + GET 200, then at t=11s (past 10s cacheTtlSec, inside 60s refreshCooldownSec) -> POST skipped, GET 200 STILL shows refresh failure!
    clearQuotaCache();
    calls.length = 0;
    getFails = false;
    now = Date.parse("2026-11-22T16:00:00Z");
    const opts = {
      baseUrl: "https://refresh-persist.example.invalid",
      refreshOnUsage: true,
      cacheTtlSec: 10,
      refreshCooldownSec: 60,
      fetchImpl,
      nowFn: () => now,
    };
    const u1 = await getAgy2ApiUsage(opts);
    assert.match(u1.plan, /配额刷新失败/);

    now += 11_000;
    const u2 = await getAgy2ApiUsage(opts);
    assert.deepEqual(
      calls.filter((p) => p !== "/api/settings"),
      ["/api/accounts/refresh", "/api/accounts", "/api/accounts"],
    );
    assert.match(u2.plan, /配额刷新失败/);
    assert.ok(u2.windows.some((w) => w.name === "状态" && /配额刷新失败/.test(w.display)));

    // 3. Internal timeout (AbortError while caller signal is NOT aborted) falls back to stale cache, whereas caller abort does NOT!
    now += 11_000;
    const internalAbortFetch = async (url) => {
      if (url.endsWith("/api/accounts")) {
        throw new DOMException("The operation was aborted.", "AbortError");
      }
      return makeJsonResponse({ error: "unexpected" }, 500);
    };
    const staleOnTimeout = await getAgy2ApiUsage({ ...opts, fetchImpl: internalAbortFetch });
    assert.match(staleOnTimeout.plan, /旧缓存/);

    now += 11_000;
    const callerCtl = new AbortController();
    const abortPromise = getAgy2ApiUsage({
      ...opts,
      signal: callerCtl.signal,
      fetchImpl: async (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
        }),
    });
    callerCtl.abort();
    const abortedRes = await abortPromise;
    assert.ok(abortedRes.error);
    assert.doesNotMatch(JSON.stringify(abortedRes), /PRO ×1|旧缓存/);

    // 4. Sole waiter abort on quota fetch does not poison immediate next call
    clearQuotaCache();
    let qAttempt = 0;
    const qCtl = new AbortController();
    const qP1 = getAgy2ApiUsage({
      baseUrl: "https://quota-abort-recover.example.invalid",
      refreshOnUsage: false,
      signal: qCtl.signal,
      fetchImpl: async (_url, init) => {
        qAttempt++;
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
        });
      },
    });
    qCtl.abort();
    const qR1 = await qP1;
    assert.ok(qR1.error);
    const qR2 = await getAgy2ApiUsage({
      baseUrl: "https://quota-abort-recover.example.invalid",
      refreshOnUsage: false,
      fetchImpl: async () =>
        makeJsonResponse({
          accounts: [{ id: "ok@example.com", state: "ready", tier: "free-tier" }],
        }),
    });
    assert.equal(qR2.plan, "FREE ×1");
    assert.equal(qAttempt, 1);
  });

  it("keeps shared pool available when only one peer is cooled and avoids non-aside 100 when an uncooled member has unknown quota", () => {
    const nowMs = Date.parse("2026-11-22T12:00:00Z");
    const futureCool = "2026-11-22T14:00:00.000Z";
    const futureReset = "2026-11-29T06:00:00Z";

    // Repro 1: A and B share Gemini bucket at 100%, only A has group cooldown -> B keeps component at 0% used
    const sharedCooledOne = computeAgy2ApiUsage(
      [
        {
          id: "a@example.com",
          state: "cooling",
          tier: "free-tier",
          shared: { gemini: ["b@example.com"] },
          cooldown: { gemini: futureCool },
          quota: [{ bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 1.0, reset_time: futureReset }],
        },
        {
          id: "b@example.com",
          state: "ready",
          tier: "free-tier",
          shared: { gemini: ["a@example.com"] },
          quota: [{ bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 1.0, reset_time: futureReset }],
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: { "gemini-fixture": { id: "gemini-fixture" } },
        modelQuotaGroupMap: new Map([["gemini-fixture", "gemini"]]),
      },
    );
    const sharedWin = sharedCooledOne.windows.find((w) => !w.aside && w.model === "gemini-fixture");
    assert.ok(sharedWin);
    assert.equal(sharedWin.used, 0);

    // Repro 2: A has model cooldown, B has unknown quota and NO cooldown -> must NOT emit non-aside used: 100
    const unknownPeerUncooled = computeAgy2ApiUsage(
      [
        {
          id: "a@example.com",
          state: "cooling",
          tier: "free-tier",
          cooldown: { "gemini-fixture": futureCool },
          quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.8 }],
        },
        {
          id: "b@example.com",
          state: "ready",
          tier: "free-tier",
          quota: [],
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: { "gemini-fixture": { id: "gemini-fixture" } },
        modelQuotaGroupMap: new Map([["gemini-fixture", "gemini"]]),
      },
    );
    assert.equal(
      unknownPeerUncooled.windows.some((w) => !w.aside && w.model === "gemini-fixture" && w.used === 100),
      false,
    );
  });

  it("never leaks upstream JSON parse error text, persists partial refresh count across GET failures and refreshOnUsage toggles, and isolates caller cancel from stale-eligible peers", async () => {
    let now = Date.parse("2026-11-22T15:00:00Z");

    // 1. POST 503 + GET malformed JSON -> error must NOT leak raw response body snippet
    const badJsonUsage = await getAgy2ApiUsage({
      baseUrl: "https://malformed-json.example.invalid",
      refreshOnUsage: true,
      fetchImpl: async (url) => {
        if (String(url).endsWith("/api/accounts/refresh")) {
          return makeJsonResponse({ error: "refresh err" }, 503);
        }
        return new Response("fixture-private-leak-body", {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
      nowFn: () => now,
    });
    assert.ok(badJsonUsage.error);
    assert.doesNotMatch(badJsonUsage.error, /fixture-private-leak/);

    // 2. Partial failure (1 account) persists across refreshOnUsage: false toggle AND across stale GET failure
    let mode = "partial";
    const toggleFetch = async (url) => {
      if (String(url).endsWith("/api/accounts/refresh")) {
        return makeJsonResponse({
          accounts: [
            {
              id: "ok@example.com",
              state: "ready",
              tier: "free-tier",
              quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.9 }],
            },
          ],
          failed: { "bad@example.com": "secret error" },
        });
      }
      if (mode === "get_fail") {
        return makeJsonResponse({ error: "down" }, 503);
      }
      return makeJsonResponse({
        accounts: [
          {
            id: "ok@example.com",
            state: "ready",
            tier: "free-tier",
            quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.9 }],
          },
        ],
      });
    };
    const baseOpts = {
      baseUrl: "https://partial-persist.example.invalid",
      cacheTtlSec: 10,
      refreshCooldownSec: 60,
      fetchImpl: toggleFetch,
      nowFn: () => now,
    };
    const p1 = await getAgy2ApiUsage({ ...baseOpts, refreshOnUsage: true });
    assert.match(p1.plan, /部分配额刷新失败（1 个账号）/);

    // Toggle refreshOnUsage: false past TTL, then back to true inside 60s cooldown (before next POST) -> STILL shows partial failure!
    now += 15_000;
    await getAgy2ApiUsage({ ...baseOpts, refreshOnUsage: false });
    now += 15_000;
    const p2 = await getAgy2ApiUsage({ ...baseOpts, refreshOnUsage: true });
    assert.match(p2.plan, /部分配额刷新失败（1 个账号）/);

    // GET failure -> stale cache STILL keeps partial failure count alongside stale indicator
    now += 15_000;
    mode = "get_fail";
    const p3 = await getAgy2ApiUsage({ ...baseOpts, refreshOnUsage: true });
    assert.match(p3.plan, /旧缓存/);
    assert.match(p3.plan, /部分配额刷新失败（1 个账号）/);

    // 3. Pre-warm stale cache, then A (with signal) and B (without signal) request GET; cancel A, then GET returns 503 -> B still gets stale cache!
    clearQuotaCache();
    let warmOk = true;
    const pendingResolvers = [];
    const raceFetch = async (url, init) => {
      assert.ok(String(url).endsWith("/api/accounts"));
      if (warmOk) {
        return makeJsonResponse({
          accounts: [{ id: "warm@example.com", state: "ready", tier: "pro-tier" }],
        });
      }
      return new Promise((resolve, reject) => {
        if (init?.signal?.aborted) {
          reject(init.signal.reason);
          return;
        }
        init?.signal?.addEventListener("abort", () => reject(init.signal.reason), { once: true });
        pendingResolvers.push(() => resolve(makeJsonResponse({ error: "unavailable" }, 503)));
      });
    };
    now = Date.parse("2026-11-22T18:00:00Z");
    await getAgy2ApiUsage({
      baseUrl: "https://stale-peer.example.invalid",
      refreshOnUsage: false,
      cacheTtlSec: 5,
      fetchImpl: raceFetch,
      nowFn: () => now,
    });
    warmOk = false;
    now += 10_000;
    const ctlA = new AbortController();
    const resA = getAgy2ApiUsage({
      baseUrl: "https://stale-peer.example.invalid",
      refreshOnUsage: false,
      cacheTtlSec: 5,
      signal: ctlA.signal,
      fetchImpl: raceFetch,
      nowFn: () => now,
    });
    const resB = getAgy2ApiUsage({
      baseUrl: "https://stale-peer.example.invalid",
      refreshOnUsage: false,
      cacheTtlSec: 5,
      fetchImpl: raceFetch,
      nowFn: () => now,
    });
    ctlA.abort();
    const outA = await resA;
    assert.ok(outA.error);
    for (const r of pendingResolvers) r();
    const outB = await resB;
    assert.match(outB.plan, /旧缓存/);
  });

  it("caps account details with maxAccountDetails and inserts grid alignment row on odd pool summaries", () => {
    const accounts = [
      {
        id: "a@example.com",
        label: "Acc A",
        state: "ready",
        tier: "free-tier",
        quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.9 }],
        quota_at: "2026-11-22T14:55:00Z",
      },
      {
        id: "b@example.com",
        label: "Acc B",
        state: "pending",
        tier: "free-tier",
      },
      {
        id: "c@example.com",
        label: "Acc C",
        state: "error",
        tier: "free-tier",
      },
    ];
    const usage = computeAgy2ApiUsage(accounts, {
      maxAccountDetails: 2,
      discoveredModels: { "gemini-4-neon": { id: "gemini-4-neon", name: "Gemini 4 Neon", family: "Gemini" } },
      modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
    });

    // Only 1 pool summary (5 hours) -> odd count -> "账号池" alignment row inserted
    assert.ok(usage.windows.some((w) => w.name === "账号池" && w.display === "1/3 在线" && w.aside));
    assert.ok(usage.windows.some((w) => w.name === "Acc A · FREE"));
    assert.ok(usage.windows.some((w) => w.name === "Acc B · FREE" && w.display === "待就绪"));
    assert.equal(usage.windows.some((w) => w.name === "Acc C · FREE"), false);
    assert.ok(usage.windows.some((w) => w.name === "其他账号" && w.display === "另有 1 个账号"));
  });

  it("filters by API_KEY_ACCOUNTS and /api/accounts/{id}/models, isolates variant vs bare cooldowns, respects QUOTA_RESERVE_PERCENT", async () => {
    const nowMs = Date.parse("2026-11-24T10:00:00Z");
    const root = "https://per-account.example.invalid";

    const usage = await getAgy2ApiUsage({
      baseUrl: root,
      apiKey: "sk-bound",
      refreshOnUsage: false,
      showAccountDetails: true,
      discoveredModels: {
        "gemini-4-carbon": { id: "gemini-4-carbon", name: "Gemini 4 Carbon", family: "Gemini" },
        "gemini-4-carbon-low": { id: "gemini-4-carbon-low", name: "Gemini 4 Carbon (Low)", family: "Gemini" },
        "gemini-4-carbon-high": { id: "gemini-4-carbon-high", name: "Gemini 4 Carbon (High)", family: "Gemini" },
        "alias-claude": { id: "alias-claude", name: "Alias Claude", family: "Claude" },
      },
      modelQuotaGroupMap: new Map([
        ["gemini-4-carbon", "gemini"],
        ["gemini-4-carbon-low", "gemini"],
        ["gemini-4-carbon-high", "gemini"],
        ["alias-claude", "3p"],
      ]),
      modelMetadataMap: new Map([
        ["gemini-4-carbon", { thinkingLevels: ["low", "high"] }],
        ["alias-claude", { isAlias: true, aliasTarget: "claude-opus-5-5", thinkingLevels: ["low", "high"] }],
      ]),
      nowFn: () => nowMs,
      fetchImpl: async (url) => {
        const p = new URL(url).pathname;
        if (p === "/api/settings") {
          return makeJsonResponse({
            API_KEYS: "sk-bound,sk-other",
            API_KEY_ACCOUNTS: "sk-bound:acc-1|acc-2",
            MODEL_MAPPING: "alias-claude:claude-opus-5-5",
            QUOTA_RESERVE_PERCENT: "10",
          });
        }
        if (p === "/api/accounts") {
          return makeJsonResponse({
            accounts: [
              {
                id: "acc-1",
                label: "Bound1",
                state: "ready",
                tier: "free-tier",
                cooldown: { "gemini-4-carbon-low": "2026-11-24T11:00:00Z" },
                quota_at: "2026-11-24T09:55:00Z",
                quota: [
                  { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.8, reset_time: "2026-11-24T13:00:00Z" },
                  { bucket_id: "3p-5h", window: "5h", remaining_fraction: 0.1, reset_time: "2026-11-24T13:00:00Z" },
                ],
              },
              {
                id: "acc-2",
                label: "Bound2",
                state: "ready",
                tier: "free-tier",
                cooldown: {
                  "gemini-4-carbon-low": "2026-11-24T11:30:00Z",
                  "gemini-4-carbon-high": "2026-11-24T12:00:00Z",
                },
                quota_at: "2026-11-24T09:55:00Z",
                quota: [
                  { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.6, reset_time: "2026-11-24T13:00:00Z" },
                  { bucket_id: "3p-5h", window: "5h", remaining_fraction: 0.9, reset_time: "2026-11-24T13:00:00Z" },
                ],
              },
              {
                id: "acc-3-unbound",
                label: "Unbound3",
                state: "ready",
                tier: "g1-ultra-tier",
                quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 1.0 }],
              },
            ],
          });
        }
        if (p === "/api/accounts/acc-1/models") {
          return makeJsonResponse({ models: [{ id: "gemini-4-carbon" }, { id: "claude-opus-5-5" }] });
        }
        if (p === "/api/accounts/acc-2/models") {
          // acc-2 supports gemini-4-carbon (baseId matches variants too) but NOT claude-opus-5-5
          return makeJsonResponse({ models: [{ id: "gemini-4-carbon" }] });
        }
        throw new Error(`Unexpected ${url}`);
      },
    });

    // Unbound account excluded
    assert.equal(usage.plan, "FREE ×2");
    assert.equal(usage.windows.some((w) => w.name.includes("Unbound3")), false);

    // gemini-4-carbon-low: BOTH acc-1 (11:00) and acc-2 (11:30) cooled -> used: 100, earliest 11:00
    const lowWin = usage.windows.find((w) => !w.aside && w.model === "gemini-4-carbon-low");
    assert.equal(lowWin.used, 100);
    assert.equal(lowWin.resetsAt, "2026-11-24T11:00:00.000Z");

    // gemini-4-carbon-high: acc-1 is NOT cooled (80% rem), acc-2 IS cooled (0% rem) -> avg 40% rem -> 60% used
    const highWin = usage.windows.find((w) => !w.aside && w.model === "gemini-4-carbon-high");
    assert.equal(highWin.used, 60);

    // Bare gemini-4-carbon: acc-1 only has -low cooled (NOT -high) -> acc-1 NOT cooled (80% rem); acc-2 has ALL variants cooled -> avg 40% -> 60% used
    const bareWin = usage.windows.find((w) => !w.aside && w.model === "gemini-4-carbon");
    assert.equal(bareWin.used, 60);

    // alias-claude -> claude-opus-5-5: only acc-1 supports it, and acc-1's 3p-5h is 10% <= QUOTA_RESERVE_PERCENT(10%) -> 100% used!
    const aliasWin = usage.windows.find((w) => !w.aside && w.model === "alias-claude");
    assert.equal(aliasWin.used, 100);
  });

  it("handles shared 7d vs independent 5h bottleneck, weekly span=604800, used=100 min(max) recovery, array failed, and stale cache age", async () => {
    const nowMs = Date.parse("2026-11-24T10:00:00Z");

    // 1. Non-shared A(5h=0, 7d=100) + B(5h=100, 7d=0) -> used: 100, min(max) recovery
    const disJointUsage = computeAgy2ApiUsage(
      [
        {
          id: "a@x",
          state: "ready",
          quota: [
            { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0, reset_time: "2026-11-24T12:00:00Z" },
            { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 1, reset_time: "2026-11-30T00:00:00Z" },
          ],
        },
        {
          id: "b@x",
          state: "ready",
          quota: [
            { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 1, reset_time: "2026-11-24T15:00:00Z" },
            { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0, reset_time: "2026-11-28T00:00:00Z" },
          ],
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: { "gemini-4-neon": { id: "gemini-4-neon" } },
        modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
      },
    );
    const djWin = disJointUsage.windows.find((w) => !w.aside && w.model === "gemini-4-neon");
    assert.equal(djWin.used, 100);
    assert.equal(djWin.resetsAt, "2026-11-24T12:00:00.000Z");
    assert.equal(djWin.span, 18000);

    // 2. Shared weekly A(5h=0, 7d=60) + B(5h=80, 7d=60) -> used: 40 (7d bottleneck span: 604800), 5h summary averages 0 and 80 (= 60% used)
    const sharedUsage = computeAgy2ApiUsage(
      [
        {
          id: "a@x",
          state: "ready",
          shared: { gemini: ["b@x"] },
          quota: [
            { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0, reset_time: "2026-11-24T12:00:00Z" },
            { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.6, reset_time: "2026-11-29T00:00:00Z" },
          ],
        },
        {
          id: "b@x",
          state: "ready",
          shared: { gemini: ["a@x"] },
          quota: [
            { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.8, reset_time: "2026-11-24T13:00:00Z" },
            { bucket_id: "gemini-weekly", window: "weekly", remaining_fraction: 0.6, reset_time: "2026-11-29T00:00:00Z" },
          ],
        },
      ],
      {
        nowMs,
        showAccountDetails: false,
        discoveredModels: { "gemini-4-neon": { id: "gemini-4-neon" } },
        modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
      },
    );
    const shWin = sharedUsage.windows.find((w) => !w.aside && w.model === "gemini-4-neon");
    assert.equal(shWin.used, 40);
    assert.equal(shWin.span, 604800);
    assert.equal(shWin.resetsAt, "2026-11-29T00:00:00.000Z");
    const sum5h = sharedUsage.windows.find((w) => w.aside && w.name === "5 hours");
    assert.equal(sum5h.used, 60);

    // 3. Array `failed` + stale cache uses fetchedAt for expiration & marks aside:true after 60s
    clearQuotaCache();
    let now = Date.parse("2026-11-24T10:00:00Z");
    let failGet = false;
    const staleOpts = {
      baseUrl: "https://stale-age.example.invalid",
      cacheTtlSec: 5,
      refreshCooldownSec: 120,
      refreshOnUsage: true,
      discoveredModels: { "gemini-4-neon": { id: "gemini-4-neon" } },
      modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
      nowFn: () => now,
      fetchImpl: async (url) => {
        const p = new URL(url).pathname;
        if (p === "/api/accounts/refresh") {
          return makeJsonResponse({
            accounts: [
              {
                id: "a@x",
                state: "ready",
                quota: [
                  {
                    bucket_id: "gemini-5h",
                    window: "5h",
                    remaining_fraction: 0,
                    reset_time: "2026-11-24T10:00:30Z",
                  },
                ],
              },
            ],
            failed: ["bad1@x", "bad2@x"],
          });
        }
        if (p === "/api/accounts" && failGet) {
          return makeJsonResponse({ error: "down" }, 503);
        }
        return makeJsonResponse({ error: "not_found" }, 404);
      },
    };

    const fresh = await getAgy2ApiUsage(staleOpts);
    assert.match(fresh.plan, /部分配额刷新失败（2 个账号）/);
    assert.equal(fresh.windows.find((w) => !w.aside && w.model === "gemini-4-neon").used, 100);

    // Advance 90s (> 60s stale threshold, and past the 10:00:30 reset_time!) and fail GET
    now += 90_000;
    failGet = true;
    const stale = await getAgy2ApiUsage(staleOpts);
    assert.match(stale.plan, /旧缓存/);
    // Evaluated at cached.fetchedAt (10:00:00 -> still 100% used, NOT falsely renewed!) AND marked aside: true (> 60s old)
    const staleModelWin = stale.windows.find((w) => w.model === "gemini-4-neon");
    assert.equal(staleModelWin.used, 100);
    assert.equal(staleModelWin.aside, true);
  });
});

describe("fetch.mjs", () => {
  beforeEach(() => {
    clearAdminSessionCache();
    clearModelCache();
    clearPrefixEffortCache();
  });

  it("rewrites URLs and sets auth headers for all 4 protocols while preserving raw body, signal, and 2xx SSE Response", async () => {
    const calls = [];
    let streamCtl;
    const sseResp = new Response(
      new ReadableStream({
        start(c) {
          streamCtl = c;
          c.enqueue(new TextEncoder().encode("data: first\n\n"));
        },
      }),
      { status: 200, headers: { "content-type": "text/event-stream" } },
    );
    let returnSse = false;
    const fetchImpl = async (url, init) => {
      calls.push({ url, headers: new Headers(init.headers), body: init.body, signal: init.signal });
      if (returnSse) return sseResp;
      return makeJsonResponse({ ok: true });
    };

    const sdkBase = "http://127.0.0.1:8017";
    const fetcher = createAgy2ApiFetch({
      baseUrl: `${sdkBase}/v1/`,
      apiKey: "sk-pub-key",
      fetchImpl,
    });

    const gemCtl = new AbortController();
    const gemBody = '{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}';
    await fetcher(`${sdkBase}/models/gemini-4-neon:generateContent`, {
      method: "POST",
      headers: { "x-magpie-effort": "high", "x-api-key": "stale" },
      body: gemBody,
      signal: gemCtl.signal,
    });
    assert.equal(calls[0].url, "http://127.0.0.1:8017/v1beta/models/gemini-4-neon:generateContent");
    assert.equal(calls[0].headers.get("x-goog-api-key"), "sk-pub-key");
    assert.equal(calls[0].headers.get("authorization"), "Bearer sk-pub-key");
    assert.equal(calls[0].headers.get("x-api-key"), null);
    assert.equal(calls[0].headers.get("x-magpie-effort"), null);
    assert.equal(calls[0].body, gemBody);
    assert.equal(calls[0].signal, gemCtl.signal);

    const anthCtl = new AbortController();
    const anthBody = '{"model":"claude-opus-5-5","messages":[{"role":"user","content":"hi"}]}';
    await fetcher(`${sdkBase}/v1/messages`, {
      method: "POST",
      headers: { "x-goog-api-key": "stale" },
      body: anthBody,
      signal: anthCtl.signal,
    });
    assert.equal(calls[1].url, "http://127.0.0.1:8017/v1/messages");
    assert.equal(calls[1].headers.get("x-api-key"), "sk-pub-key");
    assert.equal(calls[1].headers.get("x-goog-api-key"), null);
    assert.equal(calls[1].body, anthBody);
    assert.equal(calls[1].signal, anthCtl.signal);

    returnSse = true;
    const chatCtl = new AbortController();
    const chatBody = '{"model":"gpt-oss-120b","messages":[{"role":"user","content":"hi"}]}';
    const outSse = await fetcher(`${sdkBase}/chat/completions`, {
      method: "POST",
      body: chatBody,
      signal: chatCtl.signal,
    });
    assert.equal(calls[2].url, "http://127.0.0.1:8017/v1/chat/completions");
    assert.equal(calls[2].headers.get("authorization"), "Bearer sk-pub-key");
    assert.equal(calls[2].body, chatBody);
    assert.equal(calls[2].signal, chatCtl.signal);
    assert.equal(outSse, sseResp);
    const reader = outSse.body.getReader();
    const firstChunk = await reader.read();
    assert.equal(new TextDecoder().decode(firstChunk.value), "data: first\n\n");
    streamCtl.close();
    await reader.cancel();
    returnSse = false;

    const respCtl = new AbortController();
    const respBody = '{"model":"gpt-oss-120b","input":"hi"}';
    await fetcher(`${sdkBase}/v1/responses`, {
      method: "POST",
      body: respBody,
      signal: respCtl.signal,
    });
    assert.equal(calls[3].url, "http://127.0.0.1:8017/v1/responses");
    assert.equal(calls[3].headers.get("authorization"), "Bearer sk-pub-key");
    assert.equal(calls[3].body, respBody);
    assert.equal(calls[3].signal, respCtl.signal);

    assert.equal(detectProtocol("/v1/chat/completions"), "chat");
    assert.equal(detectProtocol("/v1/responses"), "responses");
    assert.equal(detectProtocol("/v1/messages"), "anthropic");
    assert.equal(detectProtocol("/v1beta/models/gemini-4-neon:streamGenerateContent"), "gemini");
    assert.equal(
      rewriteUpstreamUrl("http://x/v1/responses?stream=true", "http://127.0.0.1:8017").url,
      "http://127.0.0.1:8017/v1/responses?stream=true",
    );
  });

  it("strips SDK-creation root only (not overlapping new root) and routes Gemini /v1/models with x-goog-api-key to /v1beta/models", async () => {
    const calls = [];
    const fetchWithSwitch = (oldRoot, newRoot, path, reqHeaders = {}) =>
      createAgy2ApiFetch({
        baseUrl: oldRoot,
        apiKey: "sk-old",
        getAuth: async () => ({
          key: "sk-new",
          metadata: { baseUrl: newRoot },
        }),
        fetchImpl: async (url, init) => {
          calls.push({ url: String(url), headers: new Headers(init.headers) });
          return makeJsonResponse({ ok: true });
        },
      })(path, {
        method: "POST",
        headers: reqHeaders,
        body: JSON.stringify({ model: "fixture-model", messages: [{ role: "user", content: "hi" }] }),
      });

    // Case 1: /proxy/old -> /proxy/new
    await fetchWithSwitch(
      "https://route.example.invalid/proxy/old",
      "https://route.example.invalid/proxy/new",
      "https://route.example.invalid/proxy/old/chat/completions",
    );
    assert.equal(calls[0].url, "https://route.example.invalid/proxy/new/v1/chat/completions");
    assert.equal(calls[0].headers.get("authorization"), "Bearer sk-new");

    // Case 2: /proxy -> /proxy/chat, SDK calls /proxy/chat/completions -> /proxy/chat/v1/chat/completions with current key
    await fetchWithSwitch(
      "https://route.example.invalid/proxy",
      "https://route.example.invalid/proxy/chat",
      "https://route.example.invalid/proxy/chat/completions",
    );
    assert.equal(calls[1].url, "https://route.example.invalid/proxy/chat/v1/chat/completions");
    assert.equal(calls[1].headers.get("authorization"), "Bearer sk-new");
    assert.equal(calls[1].headers.get("x-api-key"), null);

    // Case 3: / -> /messages, SDK calls /messages -> /messages/v1/messages with current x-api-key
    await fetchWithSwitch(
      "https://route.example.invalid",
      "https://route.example.invalid/messages",
      "https://route.example.invalid/messages",
      { "x-api-key": "sk-old" },
    );
    assert.equal(calls[2].url, "https://route.example.invalid/messages/v1/messages");
    assert.equal(calls[2].headers.get("x-api-key"), "sk-new");

    // Gemini GET /v1/models with x-goog-api-key routes to /v1beta/models
    const gemGetFetcher = createAgy2ApiFetch({
      baseUrl: "https://route.example.invalid",
      apiKey: "sk-gem",
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), headers: new Headers(init.headers) });
        return makeJsonResponse({ models: [] });
      },
    });
    await gemGetFetcher("https://route.example.invalid/v1/models", {
      method: "GET",
      headers: { "x-goog-api-key": "sk-gem" },
    });
    assert.equal(calls[3].url, "https://route.example.invalid/v1beta/models");
  });

  it("routes URLs by path structure, preserving /models/models-*, root /messages, /proxy prefixes, and query params", () => {
    const root = "https://route.example.invalid";
    assert.deepEqual(
      rewriteUpstreamUrl(`${root}/models/models-fixture:streamGenerateContent?alt=sse`, root),
      {
        protocol: "gemini",
        url: `${root}/v1beta/models/models-fixture:streamGenerateContent?alt=sse`,
      },
    );
    assert.equal(rewriteUpstreamUrl(`${root}/v1/models`, root).url, `${root}/v1/models`);

    const msgRoot = "https://route.example.invalid/messages";
    assert.deepEqual(
      rewriteUpstreamUrl(`${msgRoot}/chat/completions?a=1&a=2`, msgRoot),
      {
        protocol: "chat",
        url: `${msgRoot}/v1/chat/completions?a=1&a=2`,
      },
    );

    const proxyRoot = "https://route.example.invalid/proxy";
    assert.deepEqual(
      rewriteUpstreamUrl(`${proxyRoot}/v1beta/interactions?x=1`, proxyRoot),
      {
        protocol: "other",
        url: `${proxyRoot}/v1beta/interactions?x=1`,
      },
    );
  });

  it("re-runs sanitizeRequestBody in provider fetch across all 4 protocols, idempotently, and fails open on error", async () => {
    const sent = [];
    const fetchImpl = async (url, init) => {
      sent.push({ url, headers: new Headers(init.headers), body: init.body });
      return makeJsonResponse({ ok: true });
    };

    // (a) Middleware skipped -> Anthropic request still sanitized in fetch
    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
      getPluginOptions: () => ({ promptSanitizer: true }),
    });
    const rawAnth = JSON.stringify({
      model: "claude-opus-5-5",
      max_tokens: 4096,
      system: [
        { type: "text", text: "x-anthropic-billing-header: cc_version=2.1.278;\nFollow instructions." },
        { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
      ],
      messages: [{ role: "user", content: "hi" }],
    });
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(rawAnth)) },
      body: rawAnth,
    });
    const parsedAnth = JSON.parse(sent[0].body);
    assert.equal(sent[0].headers.get("content-length"), null);
    assert.equal(JSON.stringify(parsedAnth).includes("x-anthropic-billing-header"), false);
    assert.equal(JSON.stringify(parsedAnth).includes("You are Claude Code"), false);
    assert.equal(JSON.stringify(parsedAnth).includes("You are Antigravity"), true);

    // (b) Already sanitized body -> exact byte-identical pass-through
    const alreadyClean = '{"model":"claude-opus-5-5", "max_tokens": 4096, "system": [{"type":"text","text":"You are Antigravity."}], "messages":[{"role":"user","content":"hi"}]}';
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(alreadyClean)) },
      body: alreadyClean,
    });
    assert.equal(sent[1].body, alreadyClean);
    assert.equal(sent[1].headers.get("content-length"), String(Buffer.byteLength(alreadyClean)));

    // (c) promptSanitizer: false -> untouched
    const disabledFetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
      getPluginOptions: () => ({ promptSanitizer: false }),
    });
    await disabledFetcher("http://localhost/v1/messages", {
      method: "POST",
      body: rawAnth,
    });
    assert.equal(sent[2].body, rawAnth);

    // (d) Gemini, Chat, Responses minimal cases + fail-open when getPluginOptions throws
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: "You are Claude Code, Anthropic's official CLI for Claude." }] },
        contents: [{ role: "user", parts: [{ text: "hi" }] }],
      }),
    });
    assert.equal(sent[3].body.includes("You are Antigravity"), true);

    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        messages: [
          { role: "system", content: "You are Claude Code, Anthropic's official CLI for Claude." },
          { role: "user", content: "hi" },
        ],
      }),
    });
    assert.equal(sent[4].body.includes("You are Antigravity"), true);

    await fetcher("http://localhost/v1/responses", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        instructions: "You are Claude Code, Anthropic's official CLI for Claude.",
        input: "hi",
      }),
    });
    assert.equal(sent[5].body.includes("You are Antigravity"), true);

    const throwingFetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
      getPluginOptions: () => {
        throw new Error("options read boom");
      },
    });
    await throwingFetcher("http://localhost/v1/messages", {
      method: "POST",
      body: rawAnth,
    });
    assert.equal(sent[6].body, rawAnth);
  });

  it("passes xhigh through only for xhigh-capable Gemini models without forcing includeThoughts or shadowing snake_case", async () => {
    const sentBodies = [];
    const fetchImpl = async (url, init) => {
      if (url.endsWith("/api/models")) {
        return makeJsonResponse({
          models: [
            {
              id: "gemini-4-neon",
              provider: "MODEL_PROVIDER_GOOGLE",
              thinking_levels: ["low", "medium", "high", "xhigh"],
            },
            {
              id: "gemini-3-flash",
              provider: "MODEL_PROVIDER_GOOGLE",
              thinking_levels: ["low", "high"],
            },
          ],
        });
      }
      sentBodies.push(JSON.parse(init.body));
      return makeJsonResponse({ candidates: [] });
    };

    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
    });

    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      headers: { "x-magpie-effort": "xhigh" },
      body: JSON.stringify({
        generationConfig: { thinkingConfig: { thinkingBudget: 8192, thinkingLevel: "high" } },
        contents: [{ role: "user", parts: [{ text: "hi" }] }],
      }),
    });

    assert.deepEqual(sentBodies[0].generationConfig.thinkingConfig, {
      thinkingLevel: "xhigh",
    });

    // snake_case config preserves temperature, max_output_tokens, include_thoughts, and avoids creating generationConfig
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      headers: { "x-magpie-effort": "xhigh" },
      body: JSON.stringify({
        generation_config: {
          temperature: 0.1,
          max_output_tokens: 9,
          thinking_config: { include_thoughts: false, thinking_budget: 8 },
        },
        contents: [{ role: "user", parts: [{ text: "hi" }] }],
      }),
    });
    assert.equal(sentBodies[1].generationConfig, undefined);
    assert.equal(sentBodies[1].generation_config.temperature, 0.1);
    assert.equal(sentBodies[1].generation_config.max_output_tokens, 9);
    assert.deepEqual(sentBodies[1].generation_config.thinking_config, {
      include_thoughts: false,
      thinking_level: "xhigh",
    });

    // Explicit thinking_budget: 0 (disabled) is not overridden to xhigh
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      headers: { "x-magpie-effort": "xhigh" },
      body: JSON.stringify({
        generation_config: { thinking_config: { thinking_budget: 0 } },
        contents: [{ role: "user", parts: [{ text: "hi" }] }],
      }),
    });
    assert.equal(sentBodies[2].generation_config.thinking_config.thinking_budget, 0);
    assert.equal(sentBodies[2].generation_config.thinking_config.thinking_level, undefined);

    await fetcher("http://localhost/v1beta/models/gemini-3-flash:generateContent", {
      method: "POST",
      headers: { "x-magpie-effort": "xhigh" },
      body: JSON.stringify({
        generationConfig: { thinkingConfig: { thinkingLevel: "high" } },
        contents: [{ role: "user", parts: [{ text: "hi" }] }],
      }),
    });

    // gemini-3-flash does not support xhigh -> left at "high"
    assert.equal(sentBodies[3].generationConfig.thinkingConfig.thinkingLevel, "high");
  });

  it("preserves warm cache effort on auxiliary downgrades across all 4 protocols (gemini, anthropic, chat, responses)", async () => {
    const sent = [];
    const fetchImpl = async (url, init) => {
      sent.push({ url, body: JSON.parse(init.body) });
      return makeJsonResponse({ ok: true });
    };

    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
      cacheAffinityMinBodyBytes: 128,
      preserveCacheEffort: true,
    });

    const bigText = "x".repeat(300);

    // 1. Chat (/v1/chat/completions)
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "high",
        max_completion_tokens: 32000,
        messages: [
          { role: "system", content: "sys-chat" },
          { role: "user", content: bigText },
        ],
      }),
    });
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 2048,
        messages: [
          { role: "system", content: "sys-chat" },
          { role: "user", content: bigText },
          { role: "assistant", content: "answer" },
          { role: "user", content: "summarize title" },
        ],
      }),
    });
    assert.equal(sent[1].body.reasoning_effort, "high");

    // 2. Responses (/v1/responses)
    await fetcher("http://localhost/v1/responses", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        instructions: "sys-resp",
        reasoning: { effort: "high", summary: "concise" },
        max_output_tokens: 32000,
        input: [{ role: "user", content: bigText }],
      }),
    });
    await fetcher("http://localhost/v1/responses", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        instructions: "sys-resp",
        reasoning: { effort: "low", summary: "auto" },
        max_output_tokens: 1024,
        input: [
          { role: "user", content: bigText },
          { role: "assistant", content: "done" },
        ],
      }),
    });
    assert.equal(sent[3].body.reasoning.effort, "high");
    assert.equal(sent[3].body.reasoning.summary, "auto");

    // 3. Anthropic (/v1/messages): disabled thinking must pass through untouched (never raise max_tokens);
    // adaptive + output_config only updates effort; budget_tokens only updates when restoredBudget < max_tokens
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({
        model: "claude-opus-5-5",
        system: "sys-anth",
        max_tokens: 32000,
        thinking: { type: "enabled", budget_tokens: 4096 },
        messages: [{ role: "user", content: bigText }],
      }),
    });
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({
        model: "claude-opus-5-5",
        system: "sys-anth",
        max_tokens: 1024,
        thinking: { type: "disabled" },
        messages: [
          { role: "user", content: bigText },
          { role: "assistant", content: "ok" },
        ],
      }),
    });
    assert.deepEqual(sent[5].body.thinking, { type: "disabled" });
    assert.equal(sent[5].body.max_tokens, 1024);

    // Budget-based aux with max_tokens=2048 <= restoredBudget(4096) -> skipped, max_tokens untouched
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({
        model: "claude-opus-5-5",
        system: "sys-anth",
        max_tokens: 2048,
        thinking: { type: "enabled", budget_tokens: 512 },
        messages: [
          { role: "user", content: bigText },
          { role: "assistant", content: "ok" },
        ],
      }),
    });
    assert.deepEqual(sent[6].body.thinking, { type: "enabled", budget_tokens: 512 });
    assert.equal(sent[6].body.max_tokens, 2048);

    // Budget-based aux with max_tokens=8000 (> restoredBudget 4096 and <= 8192 aux cap) -> restores budget_tokens=4096, keeps max_tokens=8000
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({
        model: "claude-opus-5-5",
        system: "sys-anth",
        max_tokens: 8000,
        thinking: { type: "enabled", budget_tokens: 512 },
        messages: [
          { role: "user", content: bigText },
          { role: "assistant", content: "ok" },
        ],
      }),
    });
    assert.deepEqual(sent[7].body.thinking, { type: "enabled", budget_tokens: 4096 });
    assert.equal(sent[7].body.max_tokens, 8000);

    // Adaptive + output_config.effort + format -> only updates effort, preserves thinking & format
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({
        model: "claude-opus-5-5",
        system: "sys-anth-adapt",
        max_tokens: 32000,
        thinking: { type: "adaptive" },
        output_config: { effort: "high" },
        messages: [{ role: "user", content: bigText }],
      }),
    });
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({
        model: "claude-opus-5-5",
        system: "sys-anth-adapt",
        max_tokens: 2048,
        thinking: { type: "adaptive" },
        output_config: { effort: "low", format: { type: "json_schema", schema: { type: "object" } } },
        messages: [
          { role: "user", content: bigText },
          { role: "assistant", content: "ok" },
        ],
      }),
    });
    assert.deepEqual(sent[9].body.thinking, { type: "adaptive" });
    assert.deepEqual(sent[9].body.output_config, {
      effort: "high",
      format: { type: "json_schema", schema: { type: "object" } },
    });
    assert.equal(sent[9].body.max_tokens, 2048);

    // 4. Gemini (/v1beta/models/...): only updates thinkingLevel, preserves includeThoughts
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: "sys-gem" }] },
        generationConfig: { maxOutputTokens: 32000, thinkingConfig: { thinkingLevel: "high", includeThoughts: true } },
        contents: [{ role: "user", parts: [{ text: bigText }] }],
      }),
    });
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: "sys-gem" }] },
        generationConfig: { maxOutputTokens: 1024, thinkingConfig: { thinkingLevel: "low", includeThoughts: false } },
        contents: [
          { role: "user", parts: [{ text: bigText }] },
          { role: "model", parts: [{ text: "ok" }] },
        ],
      }),
    });
    assert.equal(sent[11].body.generationConfig.thinkingConfig.thinkingLevel, "high");
    assert.equal(sent[11].body.generationConfig.thinkingConfig.includeThoughts, false);

    // Explicit effort-suffixed model is untouched
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b-low",
        reasoning_effort: "low",
        max_completion_tokens: 1024,
        messages: [
          { role: "system", content: "sys-chat" },
          { role: "user", content: bigText },
        ],
      }),
    });
    assert.equal(sent[12].body.reasoning_effort, "low");

    // Option preserveCacheEffort = false disables restoration
    const disabledAffFetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
      cacheAffinityMinBodyBytes: 128,
      preserveCacheEffort: false,
    });
    await disabledAffFetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 1024,
        messages: [
          { role: "system", content: "sys-chat" },
          { role: "user", content: bigText },
        ],
      }),
    });
    assert.equal(sent[13].body.reasoning_effort, "low");

    // Anthropic request with message-level output_config skips cache affinity read/write/align
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "x-session-id": "anth-msg-override" },
      body: JSON.stringify({
        model: "claude-opus-5-5",
        system: "sys-msg-ovr",
        max_tokens: 32000,
        output_config: { effort: "high" },
        messages: [{ role: "user", content: bigText }],
      }),
    });
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "x-session-id": "anth-msg-override" },
      body: JSON.stringify({
        model: "claude-opus-5-5",
        system: "sys-msg-ovr",
        max_tokens: 2048,
        output_config: { effort: "low" },
        messages: [
          { role: "user", content: bigText },
          { role: "system", content: "override", output_config: { effort: "none" } },
        ],
      }),
    });
    assert.equal(sent[15].body.output_config.effort, "low");
    assert.equal(sent[15].body.messages[1].output_config.effort, "none");
  });

  it("isolates identical prefixes by session and API key, and warms only when res.ok", async () => {
    const root = "https://effort.example.invalid";
    const seen = [];
    let nextStatus = 200;
    const fetchImpl = async (url, init) => {
      assert.equal(new URL(url).pathname, "/v1/chat/completions");
      const hdrs = new Headers(init.headers);
      assert.equal(hdrs.get("x-agy2api-cache-session"), null);
      seen.push([hdrs.get("authorization"), JSON.parse(init.body)]);
      return makeJsonResponse({ choices: [{ finish_reason: "stop" }] }, nextStatus);
    };

    const a = createAgy2ApiFetch({ baseUrl: root, apiKey: "fixture-a", fetchImpl, cacheAffinityMinBodyBytes: 64 });
    const b = createAgy2ApiFetch({ baseUrl: root, apiKey: "fixture-b", fetchImpl, cacheAffinityMinBodyBytes: 64 });

    const bigUser = "x".repeat(200);
    // HTTP 500 first request must NOT warm cache
    nextStatus = 500;
    await a(`${root}/chat/completions`, {
      method: "POST",
      headers: { "x-session-id": "fixture-500" },
      body: JSON.stringify({
        model: "fixture-model",
        reasoning_effort: "high",
        max_completion_tokens: 32000,
        messages: [{ role: "user", content: bigUser }],
      }),
    });
    nextStatus = 200;
    await a(`${root}/chat/completions`, {
      method: "POST",
      headers: { "x-session-id": "fixture-500" },
      body: JSON.stringify({
        model: "fixture-model",
        reasoning_effort: "low",
        max_completion_tokens: 2048,
        messages: [{ role: "user", content: bigUser }, { role: "user", content: "follow-up" }],
      }),
    });
    assert.equal(seen[1][1].reasoning_effort, "low");

    // Different sessions & API keys with identical prefix stay isolated
    await a(`${root}/chat/completions`, {
      method: "POST",
      headers: { "x-agy2api-cache-session": "sess-1" },
      body: JSON.stringify({
        model: "fixture-model",
        reasoning_effort: "high",
        max_completion_tokens: 32000,
        messages: [{ role: "user", content: bigUser }],
      }),
    });
    await a(`${root}/chat/completions`, {
      method: "POST",
      headers: { "x-agy2api-cache-session": "sess-2" },
      body: JSON.stringify({
        model: "fixture-model",
        reasoning_effort: "low",
        max_completion_tokens: 2048,
        messages: [{ role: "user", content: bigUser }, { role: "user", content: "follow-up" }],
      }),
    });
    await b(`${root}/chat/completions`, {
      method: "POST",
      headers: { "x-agy2api-cache-session": "sess-1" },
      body: JSON.stringify({
        model: "fixture-model",
        reasoning_effort: "low",
        max_completion_tokens: 2048,
        messages: [{ role: "user", content: bigUser }, { role: "user", content: "follow-up" }],
      }),
    });
    await a(`${root}/chat/completions`, {
      method: "POST",
      headers: { "x-agy2api-cache-session": "sess-1" },
      body: JSON.stringify({
        model: "fixture-model",
        reasoning_effort: "low",
        max_completion_tokens: 2048,
        messages: [{ role: "user", content: bigUser }, { role: "user", content: "follow-up" }],
      }),
    });

    assert.equal(seen[3][1].reasoning_effort, "low");
    assert.equal(seen[4][1].reasoning_effort, "low");
    assert.equal(seen[5][1].reasoning_effort, "high");
  });

  it("normalizes 429, 503/529, and 400 content rejection with strict semantic matching", async () => {
    assert.equal(hasWholeModelToken("quota exceeded for gemini-4-argon-medium", "gemini-4-argon"), false);
    assert.equal(hasWholeModelToken("model gemini-4-argon: quota exceeded", "gemini-4-argon"), true);

    // 429 explicit QUOTA_EXHAUSTED adds model context without synthesizing extra status/quota text
    const norm429 = normalizeUpstreamErrorResponse(
      JSON.stringify({
        error: {
          message: "upstream 429 RESOURCE_EXHAUSTED QUOTA_EXHAUSTED: Quota exhausted for gemini-4-argon-medium",
        },
      }),
      429,
      "gemini-4-argon",
    );
    const body429 = JSON.parse(norm429.body);
    assert.equal(hasWholeModelToken(body429.error.message, "gemini-4-argon"), true);
    assert.equal(body429.error.model, "gemini-4-argon");

    // 429 "No available accounts" or generic RESOURCE_EXHAUSTED without explicit quota reason -> null
    assert.equal(
      normalizeUpstreamErrorResponse(
        JSON.stringify({ error: { message: "No available accounts for request" } }),
        429,
        "gemini-4-argon",
      ),
      null,
    );
    assert.equal(
      normalizeUpstreamErrorResponse(
        JSON.stringify({ error: { status: "RESOURCE_EXHAUSTED", message: "Too many requests" } }),
        429,
        "gemini-4-argon",
      ),
      null,
    );

    // 503 service-wide unavailability MUST pass through untouched (null)
    assert.equal(
      normalizeUpstreamErrorResponse(
        JSON.stringify({ error: { message: "No ready accounts available" } }),
        503,
        "gemini-4-neon",
      ),
      null,
    );
    assert.equal(
      normalizeUpstreamErrorResponse("server shutting down", 503, "gemini-4-neon"),
      null,
    );
    assert.equal(normalizeUpstreamErrorResponse("", 503, "gemini-4-neon"), null);

    // 503 explicit MODEL_CAPACITY_EXHAUSTED / 529 Overloaded -> adds model context without fabricating overloaded_error
    const norm503 = normalizeUpstreamErrorResponse(
      JSON.stringify({
        error: {
          type: "server_error",
          code: "upstream_error",
          param: null,
          message: "Service unavailable: upstream 503 UNAVAILABLE MODEL_CAPACITY_EXHAUSTED: fixture",
        },
      }),
      503,
      "gemini-4-neon",
    );
    const body503 = JSON.parse(norm503.body);
    assert.equal(body503.error.type, "server_error");
    assert.equal(body503.error.code, "upstream_error");
    assert.equal(hasWholeModelToken(body503.error.message, "gemini-4-neon"), true);

    const norm529 = normalizeUpstreamErrorResponse(
      JSON.stringify({ error: { message: "Overloaded: capacity reached" } }),
      529,
      "claude-opus-5-5",
    );
    const body529 = JSON.parse(norm529.body);
    assert.equal(body529.error.type, undefined);
    assert.equal(hasWholeModelToken(body529.error.message, "claude-opus-5-5"), true);

    // 400 OpenAI content rejection preserves original sentence and appends flagged wording
    const normOpenAI400 = normalizeUpstreamErrorResponse(
      JSON.stringify({
        error: {
          code: "invalid_prompt",
          type: "invalid_request_error",
          message: "Upstream rejected the request content (not a quota or rate limit)",
        },
      }),
      400,
      "gpt-oss-120b",
    );
    const oai400 = JSON.parse(normOpenAI400.body);
    assert.equal(oai400.error.code, "invalid_prompt");
    assert.match(oai400.error.message, /not a quota or rate limit/);
    assert.match(oai400.error.message, /flagged/i);

    // 400 Anthropic content rejection (Go fixed prefix and Upstream rejected the input: SAFETY|BLOCKLIST|PROHIBITED_CONTENT)
    const normAnth400 = normalizeUpstreamErrorResponse(
      JSON.stringify({
        type: "error",
        error: {
          type: "invalid_request_error",
          message: "Upstream rejected the request content",
        },
      }),
      400,
      "claude-opus-5-5",
    );
    const anth400 = JSON.parse(normAnth400.body);
    assert.equal(anth400.error.code, "content_policy_violation");
    assert.equal(anth400.error.type, "invalid_request_error");
    assert.equal(anth400.error.message, "Upstream rejected the request content");

    for (const reason of ["SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT"]) {
      const anthRaw = normalizeUpstreamErrorResponse(
        JSON.stringify({
          type: "error",
          error: {
            type: "invalid_request_error",
            message: `Upstream rejected the input: ${reason}`,
          },
        }),
        400,
        "claude-opus-5-5",
      );
      assert.equal(JSON.parse(anthRaw.body).error.code, "content_policy_violation");
    }

    // Ordinary 400 parameter error mentioning BLOCKLIST must NOT be marked as content rejection
    assert.equal(
      normalizeUpstreamErrorResponse(
        JSON.stringify({
          type: "error",
          error: {
            type: "invalid_request_error",
            message: 'unsupported content role "BLOCKLIST"',
          },
        }),
        400,
        "claude-opus-5-5",
      ),
      null,
    );

    // 400 Gemini content rejection
    const normGem400 = normalizeUpstreamErrorResponse(
      JSON.stringify({
        error: {
          code: 400,
          status: "INVALID_ARGUMENT",
          message: "Upstream rejected the request content",
        },
      }),
      400,
      "gemini-4-neon",
    );
    const gem400 = JSON.parse(normGem400.body);
    assert.equal(gem400.error.code, 400);
    assert.equal(gem400.error.status, "INVALID_ARGUMENT");
    assert.equal(gem400.error.type, "content_policy_violation");

    // 400 ordinary bad request MUST pass through untouched
    assert.equal(
      normalizeUpstreamErrorResponse(
        JSON.stringify({ error: { code: "invalid_request", message: "max_tokens must be positive" } }),
        400,
        "claude-opus-5-5",
      ),
      null,
    );
  });

  it("preserves real HTTP status, Retry-After, exact unnormalized bytes, and skips non-JSON streams", async () => {
    const fetchImpl = async () =>
      new Response(
        JSON.stringify({
          error: {
            type: "server_error",
            code: "upstream_error",
            param: null,
            message: "Service unavailable: upstream 503 UNAVAILABLE MODEL_CAPACITY_EXHAUSTED: fixture",
          },
        }),
        {
          status: 503,
          headers: {
            "content-type": "application/json",
            "retry-after": "12",
            "x-ratelimit-remaining": "0",
          },
        },
      );

    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
    });

    const res = await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] }),
    });

    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "12");
    assert.equal(res.headers.get("x-ratelimit-remaining"), "0");
    const json = await res.json();
    assert.equal(json.error.type, "server_error");
    assert.equal(json.error.model, "gemini-4-neon");

    // Unmatched JSON preserves exact original formatting bytes
    const rawOriginal = '{  "error" : { "message" : "No available accounts" }  }';
    const rawFetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl: async () =>
        new Response(rawOriginal, {
          status: 429,
          headers: { "content-type": "application/json", "retry-after": "7" },
        }),
    });
    const rawRes = await rawFetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-oss-120b", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(rawRes.headers.get("retry-after"), "7");
    assert.equal(await rawRes.text(), rawOriginal);

    // Non-JSON response (text/event-stream or binary) is returned untouched without reading body
    const sseResp = new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("event: error\n\n"));
        },
      }),
      { status: 503, headers: { "content-type": "text/event-stream" } },
    );
    const sseFetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl: async () => sseResp,
    });
    const outSse = await sseFetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-oss-120b", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(outSse, sseResp);
    const reader = outSse.body.getReader();
    const firstChunk = await reader.read();
    assert.equal(new TextDecoder().decode(firstChunk.value), "event: error\n\n");
    await reader.cancel();
  });

  it("isolates independent sessions and honors main-session effort changes while passing 401/403/500 untouched", async () => {
    const sent = [];
    let statusToReturn = 200;
    const fetchImpl = async (url, init) => {
      if (statusToReturn !== 200) {
        return new Response(JSON.stringify({ error: { message: "upstream auth failed" } }), {
          status: statusToReturn,
        });
      }
      sent.push(JSON.parse(init.body));
      return makeJsonResponse({ ok: true });
    };

    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
      cacheAffinityMinBodyBytes: 64,
    });

    const bigA = "a".repeat(200);
    const bigB = "b".repeat(200);

    // Session A warm at high
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "high",
        max_completion_tokens: 32000,
        messages: [{ role: "user", content: bigA }],
      }),
    });

    // Session B warm at low -> must NOT be affected by Session A
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 2048,
        messages: [{ role: "user", content: bigB }],
      }),
    });
    assert.equal(sent[1].reasoning_effort, "low");

    // Main-session user switch in Session A to low (max_completion_tokens > 8192) -> updates warm entry immediately
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 16384,
        messages: [
          { role: "user", content: bigA },
          { role: "assistant", content: "ok" },
        ],
      }),
    });
    assert.equal(sent[2].reasoning_effort, "low");

    // Subsequent aux call on Session A stays low (since warm was updated to low)
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 1024,
        messages: [
          { role: "user", content: bigA },
          { role: "assistant", content: "ok2" },
        ],
      }),
    });
    assert.equal(sent[3].reasoning_effort, "low");

      // 401 / 403 / 500 pass through untouched
    for (const code of [401, 403, 500]) {
      statusToReturn = code;
      const errRes = await fetcher("http://localhost/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({ model: "gpt-oss-120b", messages: [{ role: "user", content: "hi" }] }),
      });
      assert.equal(errRes.status, code);
      const parsed = await errRes.json();
      assert.equal(parsed.error.message, "upstream auth failed");
    }
  });

  it("does not invent effort fields from header, writes back Gemini thinkingBudget, respects disabled overrides, and skips no-op xhigh serialization", async () => {
    const sent = [];
    const fetchImpl = async (url, init) => {
      if (url.endsWith("/api/models")) {
        return makeJsonResponse({
          models: [
            {
              id: "gemini-4-neon",
              provider: "MODEL_PROVIDER_GOOGLE",
              thinking_levels: ["low", "medium", "high", "xhigh"],
            },
          ],
        });
      }
      if (url.endsWith("/api/settings")) {
        return makeJsonResponse({ error: "not_found" }, 404);
      }
      sent.push({ headers: new Headers(init.headers), body: init.body });
      return makeJsonResponse({ ok: true });
    };

    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
      cacheAffinityMinBodyBytes: 64,
    });
    const bigText = "x".repeat(200);

    // 1. Chat main warms high, aux has x-magpie-effort: low header ONLY (no body field) -> must NOT invent reasoning_effort in body
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "no-invent" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "high",
        max_completion_tokens: 32000,
        messages: [{ role: "user", content: bigText }],
      }),
    });
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "no-invent", "x-magpie-effort": "low" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        max_completion_tokens: 2048,
        messages: [{ role: "user", content: bigText }, { role: "user", content: "follow-up" }],
      }),
    });
    assert.equal(JSON.parse(sent[1].body).reasoning_effort, undefined);

    // 2. Chat top-level reasoning_effort: "low" + nested reasoning.effort: "none" (disabled wins) -> NOT rewritten
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "no-invent" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        reasoning: { effort: "none" },
        max_completion_tokens: 2048,
        messages: [{ role: "user", content: bigText }, { role: "user", content: "follow-up" }],
      }),
    });
    assert.equal(JSON.parse(sent[2].body).reasoning_effort, "low");
    assert.equal(JSON.parse(sent[2].body).reasoning.effort, "none");

    // 3. Gemini thinkingBudget: 12288 warm -> aux thinkingBudget: 1024 writes back 12288
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      headers: { "x-session-id": "gem-budget" },
      body: JSON.stringify({
        generationConfig: { maxOutputTokens: 32000, thinkingConfig: { thinkingBudget: 12288 } },
        contents: [{ role: "user", parts: [{ text: bigText }] }],
      }),
    });
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      headers: { "x-session-id": "gem-budget" },
      body: JSON.stringify({
        generationConfig: { maxOutputTokens: 1024, thinkingConfig: { thinkingBudget: 1024 } },
        contents: [
          { role: "user", parts: [{ text: bigText }] },
          { role: "model", parts: [{ text: "ok" }] },
        ],
      }),
    });
    assert.equal(JSON.parse(sent[4].body).generationConfig.thinkingConfig.thinkingBudget, 12288);

    // 4. Gemini thinkingBudget: 0 + thinkingLevel: "low" + x-magpie-effort: xhigh -> disabled wins, NOT rewritten to xhigh
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      headers: { "x-magpie-effort": "xhigh" },
      body: JSON.stringify({
        generationConfig: { thinkingConfig: { thinkingBudget: 0, thinkingLevel: "low" } },
        contents: [{ role: "user", parts: [{ text: "hi" }] }],
      }),
    });
    assert.equal(JSON.parse(sent[5].body).generationConfig.thinkingConfig.thinkingLevel, "low");
    assert.equal(JSON.parse(sent[5].body).generationConfig.thinkingConfig.thinkingBudget, 0);

    // 5. Gemini already thinkingLevel: "xhigh" with no budget -> body bytes & Content-Length preserved untouched
    const rawAlreadyXhigh =
      '{"generationConfig": {"thinkingConfig": {"thinkingLevel": "xhigh"}}, "contents": [{"role": "user", "parts": [{"text": "hi"}]}]}';
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      headers: {
        "x-magpie-effort": "xhigh",
        "content-length": String(Buffer.byteLength(rawAlreadyXhigh)),
      },
      body: rawAlreadyXhigh,
    });
    assert.equal(sent[6].body, rawAlreadyXhigh);
    assert.equal(sent[6].headers.get("content-length"), String(Buffer.byteLength(rawAlreadyXhigh)));
  });

  it("does not let an earlier-started slower main request regress warm effort", async () => {
    const sent = [];
    const resolvers = [];
    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      cacheAffinityMinBodyBytes: 64,
      fetchImpl: (_url, init) => {
        sent.push(JSON.parse(init.body).reasoning_effort);
        return new Promise((resolve) => {
          resolvers.push(() => resolve(makeJsonResponse({ ok: true })));
        });
      },
    });

    const bigText = "z".repeat(200);
    const pFirst = fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "race-sess" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "xhigh",
        max_completion_tokens: 32000,
        messages: [{ role: "user", content: bigText }],
      }),
    });
    const pSecond = fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "race-sess" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "medium",
        max_completion_tokens: 32000,
        messages: [
          { role: "user", content: bigText },
          { role: "assistant", content: "step1" },
          { role: "user", content: "switch to medium" },
        ],
      }),
    });

    // Second (medium) completes FIRST, then first (xhigh) completes SECOND
    await Promise.resolve();
    resolvers[1]();
    await pSecond;
    resolvers[0]();
    await pFirst;

    const pAux = fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "race-sess" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 1024,
        messages: [
          { role: "user", content: bigText },
          { role: "assistant", content: "step2" },
          { role: "user", content: "aux" },
        ],
      }),
    });
    await Promise.resolve();
    resolvers[2]();
    await pAux;

    assert.deepEqual(sent, ["xhigh", "medium", "medium"]);
  });

  it("normalizes gzip-labeled JSON errors, strips content-encoding on miss, preserves invalid UTF-8 bytes, ignores quoted 429 text, and avoids no-op 400 serialization", async () => {
    // 1. 400 JSON with Content-Encoding: gzip still gets normalized and strips content-encoding/content-length
    const gzipFetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            type: "error",
            error: { type: "invalid_request_error", message: "Upstream rejected the input: SAFETY" },
          }),
          {
            status: 400,
            headers: {
              "content-type": "application/json",
              "content-encoding": "gzip",
              "content-length": "999",
            },
          },
        ),
    });
    const resHit = await gzipFetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({ model: "claude-opus-5-5", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(resHit.headers.get("content-encoding"), null);
    assert.equal(resHit.headers.get("content-length"), null);
    assert.equal((await resHit.json()).error.code, "content_policy_violation");

    // 2. Unmatched 400 with Content-Encoding: gzip + invalid UTF-8 raw bytes preserves exact raw bytes and strips content-encoding
    const invalidUtf8Bytes = new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]); // {"\xff":1}
    const rawMissFetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl: async () =>
        new Response(invalidUtf8Bytes, {
          status: 400,
          headers: {
            "content-type": "application/json",
            "content-encoding": "gzip",
            "content-length": String(invalidUtf8Bytes.byteLength),
          },
        }),
    });
    const resMiss = await rawMissFetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({ model: "claude-opus-5-5", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(resMiss.headers.get("content-encoding"), null);
    assert.equal(resMiss.headers.get("content-length"), null);
    assert.deepEqual(new Uint8Array(await resMiss.arrayBuffer()), invalidUtf8Bytes);

    // 3. Quoted upstream 429 text inside "No account can serve..." must NOT be rewritten
    assert.equal(
      normalizeUpstreamErrorResponse(
        JSON.stringify({
          error: {
            message:
              "No account can serve this request; last message: upstream 429 RESOURCE_EXHAUSTED QUOTA_EXHAUSTED: depleted",
          },
        }),
        429,
        "gemini-4-neon",
      ),
      null,
    );

    // 4. 400 already having code/type/flagged returns null (no-op re-serialization avoided)
    assert.equal(
      normalizeUpstreamErrorResponse(
        JSON.stringify({
          type: "error",
          error: {
            type: "invalid_request_error",
            code: "content_policy_violation",
            message: "Upstream rejected the input: SAFETY",
          },
        }),
        400,
        "claude-opus-5-5",
      ),
      null,
    );
  });

  it("handles session injection/stripping, subagent isolation, and responses previous_response_id protection across all 4 protocols + countTokens", async () => {
    const sent = [];
    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      cacheAffinityMinBodyBytes: 64,
      fetchImpl: async (url, init) => {
        let parsed = null;
        if (typeof init.body === "string") {
          try {
            parsed = JSON.parse(init.body);
          } catch {
            parsed = init.body;
          }
        }
        sent.push({
          url: String(url),
          headers: new Headers(init.headers),
          body: parsed,
        });
        return makeJsonResponse({ ok: true });
      },
    });

    const bigText = "s".repeat(200);

    // 1. Always strips internal headers (even on GET/non-gen) and injects x-session-id only when missing native session
    await fetcher("http://localhost/v1/models", {
      method: "GET",
      headers: {
        "x-magpie-session": "sess-main",
        "x-magpie-subagent": "sub-1",
        "x-agy2api-cache-session": "hash-1",
        "x-magpie-effort": "high",
        "x-magpie-custom": "drop-me",
      },
    });
    assert.equal(sent[0].headers.get("x-magpie-session"), null);
    assert.equal(sent[0].headers.get("x-magpie-subagent"), null);
    assert.equal(sent[0].headers.get("x-agy2api-cache-session"), null);
    assert.equal(sent[0].headers.get("x-magpie-effort"), null);
    assert.equal(sent[0].headers.get("x-magpie-custom"), null);
    assert.equal(sent[0].headers.get("x-session-id"), null);

    // 2. Main session vs subagent isolation (both upstream x-session-id and local preserve_cache_effort)
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-parent-1" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "high",
        max_completion_tokens: 32000,
        messages: [{ role: "user", content: bigText }],
      }),
    });
    assert.equal(sent[1].headers.get("x-session-id"), "magpie-parent-1");
    assert.equal(sent[1].headers.get("x-magpie-session"), null);

    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-parent-1", "x-magpie-subagent": "explore-1" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 1024,
        messages: [{ role: "user", content: bigText }, { role: "assistant", content: "hi" }],
      }),
    });
    assert.match(sent[2].headers.get("x-session-id"), /^magpie-sub-v1-[0-9a-f]{32}$/);
    assert.equal(sent[2].body.reasoning_effort, "low", "subagent must NOT inherit parent warm effort");

    // 3. Same main session (no subagent) aux call DOES inherit parent warm effort and uses parent x-session-id
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-parent-1" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 1024,
        messages: [{ role: "user", content: bigText }, { role: "assistant", content: "hi" }],
      }),
    });
    assert.equal(sent[3].headers.get("x-session-id"), "magpie-parent-1");
    assert.equal(sent[3].body.reasoning_effort, "high");

    // 4. Native session IDs: Anthropic JSON user_id, empty JSON session_id, plain user_id, count_tokens, countTokens
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-fallback" },
      body: JSON.stringify({
        model: "claude-opus-5-5",
        metadata: { user_id: '{"session_id":"native-anth-json"}' },
        messages: [{ role: "user", content: "hi" }],
      }),
    });
    assert.equal(sent[4].headers.get("x-session-id"), null);

    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-fallback" },
      body: JSON.stringify({
        model: "claude-opus-5-5",
        metadata: { user_id: '{"session_id":"   "}' },
        messages: [{ role: "user", content: "hi" }],
      }),
    });
    assert.equal(sent[5].headers.get("x-session-id"), "magpie-fallback");

    await fetcher("http://localhost/v1/messages/count_tokens", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-ct" },
      body: JSON.stringify({
        model: "claude-opus-5-5",
        messages: [{ role: "user", content: "hi" }],
      }),
    });
    assert.equal(sent[6].headers.get("x-session-id"), "magpie-ct");

    await fetcher("http://localhost/v1beta/models/gemini-4-neon:countTokens", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-gem-ct" },
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] }),
    });
    assert.equal(sent[7].headers.get("x-session-id"), "magpie-gem-ct");

    // 5. Responses previous_response_id without native session must NOT inject x-session-id
    await fetcher("http://localhost/v1/responses", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-resp" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        previous_response_id: "resp_abc123",
        input: "continue",
      }),
    });
    assert.equal(sent[8].headers.get("x-session-id"), null);

    // 6. Malformed JSON POST body for anthropic/chat/responses must NOT inject x-session-id
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-bad-json" },
      body: "{bad json",
    });
    assert.equal(sent[9].headers.get("x-session-id"), null);

    // 7. chat prompt_cache_key counts as native session
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-magpie-session": "magpie-ignored" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        prompt_cache_key: "pck-1",
        messages: [{ role: "user", content: "hi" }],
      }),
    });
    assert.equal(sent[10].headers.get("x-session-id"), null);
  });

  it("handles preserve_cache_effort edge cases: LRU eviction race guard, tools fingerprint, single/same physical variant skip, includeThoughts:false, between_tools, configuration_update, header slot", async () => {
    const sent = [];
    const resolvers = [];
    let delayResponses = false;
    const fetchImpl = (url, init) => {
      const u = String(url);
      if (u.endsWith("/api/models")) {
        return Promise.resolve(
          makeJsonResponse({
            models: [
              {
                id: "gemini-4-carbon",
                provider: "MODEL_PROVIDER_GOOGLE",
                thinking_levels: ["low", "medium", "high"],
                capabilities: { thinking: true },
              },
              {
                id: "gpt-single",
                provider: "MODEL_PROVIDER_OPENAI",
                thinking_levels: ["medium"],
                capabilities: { thinking: true },
              },
              {
                id: "gemini-4-neon",
                provider: "MODEL_PROVIDER_GOOGLE",
                thinking_levels: ["low", "medium", "high", "xhigh"],
                capabilities: { thinking: true },
              },
            ],
          }),
        );
      }
      if (u.endsWith("/api/settings")) {
        return Promise.resolve(makeJsonResponse({ error: "not_found" }, 404));
      }
      sent.push(JSON.parse(init.body));
      if (delayResponses) {
        return new Promise((resolve) => {
          resolvers.push(() => resolve(makeJsonResponse({ ok: true })));
        });
      }
      return Promise.resolve(makeJsonResponse({ ok: true }));
    };

    const { ensureModelsDiscovered } = await import("../lib/models.mjs");
    await ensureModelsDiscovered(DEFAULT_BASE_URL, "sk-pub", { fetchImpl });

    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      cacheAffinityMinBodyBytes: 64,
      fetchImpl,
    });
    const bigText = "p".repeat(200);

    // 1. Out-of-order slow main request cannot overwrite newer main request EVEN AFTER >256 entries evict cache!
    delayResponses = true;
    const pSlow = fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "evict-race" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "xhigh",
        max_completion_tokens: 32000,
        messages: [{ role: "user", content: bigText }],
      }),
    });
    const pFast = fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "evict-race" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "medium",
        max_completion_tokens: 32000,
        messages: [{ role: "user", content: bigText }, { role: "assistant", content: "ok" }],
      }),
    });
    await Promise.resolve();
    resolvers[1](); // fast (medium) completes first
    await pFast;

    // Evict all 256 cache entries while pSlow is STILL in flight!
    delayResponses = false;
    for (let i = 0; i < 260; i++) {
      await fetcher("http://localhost/v1/chat/completions", {
        method: "POST",
        headers: { "x-session-id": `evict-filler-${i}` },
        body: JSON.stringify({
          model: "gpt-oss-120b",
          reasoning_effort: "high",
          max_completion_tokens: 32000,
          messages: [{ role: "user", content: bigText }],
        }),
      });
    }
    resolvers[0](); // slow (xhigh) completes AFTER eviction
    await pSlow;

    // Aux request for evict-race must NOT see stale xhigh from pSlow!
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "evict-race" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 1024,
        messages: [{ role: "user", content: bigText }, { role: "assistant", content: "ok2" }],
      }),
    });
    assert.equal(sent[sent.length - 1].reasoning_effort, "low");

    // 2. Tools prefix differentiation
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "tools-sess" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "high",
        max_completion_tokens: 32000,
        tools: [{ type: "function", function: { name: "read_file" } }],
        messages: [{ role: "user", content: bigText }],
      }),
    });
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "tools-sess" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_completion_tokens: 1024,
        tools: [{ type: "function", function: { name: "different_tool" } }],
        messages: [{ role: "user", content: bigText }, { role: "assistant", content: "ok" }],
      }),
    });
    assert.equal(sent[sent.length - 1].reasoning_effort, "low");

    // 3. Single physical model & same physical effective variant (xhigh vs high on gemini-4-carbon) & -tiered suffix skip
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "single-phys" },
      body: JSON.stringify({
        model: "gpt-single",
        reasoning_effort: "high",
        max_completion_tokens: 32000,
        messages: [{ role: "user", content: bigText }],
      }),
    });
    await fetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      headers: { "x-session-id": "single-phys" },
      body: JSON.stringify({
        model: "gpt-single",
        reasoning_effort: "low",
        max_completion_tokens: 1024,
        messages: [{ role: "user", content: bigText }],
      }),
    });
    assert.equal(sent[sent.length - 1].reasoning_effort, "low");

    // gemini-4-carbon only has ["low","medium","high"]: warm xhigh vs aux high -> same physical variant -> NOT rewritten to "xhigh"
    await fetcher("http://localhost/v1beta/models/gemini-4-carbon:generateContent", {
      method: "POST",
      headers: { "x-session-id": "same-phys" },
      body: JSON.stringify({
        generationConfig: {
          maxOutputTokens: 32000,
          responseMimeType: "application/json",
          responseSchema: { type: "OBJECT" },
          thinkingConfig: { thinkingLevel: "xhigh", includeThoughts: false },
        },
        contents: [{ role: "user", parts: [{ text: bigText }] }],
      }),
    });
    await fetcher("http://localhost/v1beta/models/gemini-4-carbon:generateContent", {
      method: "POST",
      headers: { "x-session-id": "same-phys" },
      body: JSON.stringify({
        generationConfig: {
          maxOutputTokens: 1024,
          responseMimeType: "application/json",
          responseSchema: { type: "OBJECT" },
          thinkingConfig: { thinkingLevel: "high", includeThoughts: false },
        },
        contents: [{ role: "user", parts: [{ text: bigText }] }],
      }),
    });
    assert.equal(sent[sent.length - 1].generationConfig.thinkingConfig.thinkingLevel, "high");

    // Same session with aux "low" and includeThoughts:false DOES rewrite to warm "xhigh" while preserving includeThoughts:false & responseSchema!
    await fetcher("http://localhost/v1beta/models/gemini-4-carbon:generateContent", {
      method: "POST",
      headers: { "x-session-id": "same-phys" },
      body: JSON.stringify({
        generationConfig: {
          maxOutputTokens: 1024,
          responseMimeType: "application/json",
          responseSchema: { type: "OBJECT" },
          thinkingConfig: { thinkingLevel: "low", includeThoughts: false },
        },
        contents: [{ role: "user", parts: [{ text: bigText }] }],
      }),
    });
    assert.equal(sent[sent.length - 1].generationConfig.thinkingConfig.thinkingLevel, "xhigh");
    assert.equal(sent[sent.length - 1].generationConfig.thinkingConfig.includeThoughts, false);
    assert.deepEqual(sent[sent.length - 1].generationConfig.responseSchema, { type: "OBJECT" });

    // 4. Anthropic between_tools & Responses configuration_update & Responses top-level reasoning_effort ignored & header slot no body injection
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "x-session-id": "anth-bt" },
      body: JSON.stringify({
        model: "claude-opus-5-5",
        max_tokens: 32000,
        output_config: { effort: "high" },
        messages: [{ role: "user", content: bigText }],
      }),
    });
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "x-session-id": "anth-bt" },
      body: JSON.stringify({
        model: "claude-opus-5-5",
        max_tokens: 1024,
        thinking: { type: "between_tools" },
        output_config: { effort: "low" },
        messages: [{ role: "user", content: bigText }],
      }),
    });
    assert.equal(sent[sent.length - 1].output_config.effort, "low");

    await fetcher("http://localhost/v1/responses", {
      method: "POST",
      headers: { "x-session-id": "resp-cfg" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning: { effort: "high" },
        max_output_tokens: 32000,
        input: [{ role: "user", content: bigText }],
      }),
    });
    // configuration_update skipped
    await fetcher("http://localhost/v1/responses", {
      method: "POST",
      headers: { "x-session-id": "resp-cfg" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning: { effort: "low" },
        max_output_tokens: 1024,
        input: [{ role: "user", content: bigText }, { type: "configuration_update" }],
      }),
    });
    assert.equal(sent[sent.length - 1].reasoning.effort, "low");

    // Top-level reasoning_effort on responses is ignored (not rewritten)
    await fetcher("http://localhost/v1/responses", {
      method: "POST",
      headers: { "x-session-id": "resp-cfg" },
      body: JSON.stringify({
        model: "gpt-oss-120b",
        reasoning_effort: "low",
        max_output_tokens: 1024,
        input: [{ role: "user", content: bigText }],
      }),
    });
    assert.equal(sent[sent.length - 1].reasoning_effort, "low");
    assert.equal(sent[sent.length - 1].reasoning, undefined);

    // 5. preserveCacheEffort: false skips prefix cache completely while Gemini xhigh passthrough still works
    const noPresFetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      preserveCacheEffort: false,
      cacheAffinityMinBodyBytes: 64,
      fetchImpl,
    });
    await noPresFetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      headers: { "x-magpie-effort": "xhigh" },
      body: JSON.stringify({
        generationConfig: { thinkingConfig: { thinkingLevel: "high" } },
        contents: [{ role: "user", parts: [{ text: bigText }] }],
      }),
    });
    assert.equal(sent[sent.length - 1].generationConfig.thinkingConfig.thinkingLevel, "xhigh");

    // 6. Anthropic thinking.type="between_tools" (Magpie Sonnet 5.5 ThinkOff) maps to {"type":"disabled"} on messages & count_tokens and skips effort alignment
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "x-session-id": "anth-bt" },
      body: JSON.stringify({
        model: "claude-sonnet-5-5",
        max_tokens: 32000,
        output_config: { effort: "high", format: { type: "json_schema", schema: { type: "object" } } },
        messages: [{ role: "user", content: bigText }],
      }),
    });
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      headers: { "x-session-id": "anth-bt" },
      body: JSON.stringify({
        model: "claude-sonnet-5-5",
        max_tokens: 1024,
        thinking: { type: "between_tools" },
        output_config: { effort: "high", format: { type: "json_schema", schema: { type: "object" } } },
        messages: [{ role: "user", content: bigText }, { role: "user", content: "side classifier" }],
      }),
    });
    assert.deepEqual(sent[sent.length - 1].thinking, { type: "disabled" });
    assert.deepEqual(sent[sent.length - 1].output_config, {
      effort: "high",
      format: { type: "json_schema", schema: { type: "object" } },
    });

    await fetcher("http://localhost/v1/messages/count_tokens", {
      method: "POST",
      headers: { "x-session-id": "anth-bt" },
      body: JSON.stringify({
        model: "claude-sonnet-5-5",
        thinking: { type: "between_tools" },
        messages: [{ role: "user", content: "count" }],
      }),
    });
    assert.deepEqual(sent[sent.length - 1].thinking, { type: "disabled" });
  });

  it("normalizes 502 content policy, 401 kept/expired & 400 API_KEY_INVALID, 429 CooldownError/upstream 429, and 404 model_not_found", async () => {
    // 1. 502 content policy across OpenAI, Anthropic, Gemini
    const norm502Oai = normalizeUpstreamErrorResponse(
      JSON.stringify({
        error: {
          code: "upstream_502",
          message: "Internal server error: Upstream stopped generation due to content policy: PROHIBITED",
        },
      }),
      502,
      "gpt-oss-120b",
    );
    const o502 = JSON.parse(norm502Oai.body);
    assert.equal(o502.error.code, "content_policy_violation");
    assert.equal(o502.error.upstream_code, "upstream_502");

    const norm502Anth = normalizeUpstreamErrorResponse(
      JSON.stringify({
        type: "error",
        error: { type: "api_error", message: "Upstream stopped generation due to content policy: SAFETY" },
      }),
      502,
      "claude-opus-5-5",
    );
    assert.equal(JSON.parse(norm502Anth.body).error.code, "content_policy_violation");

    const norm502Gem = normalizeUpstreamErrorResponse(
      JSON.stringify({
        error: { code: 502, status: "INTERNAL", message: "Upstream stopped generation due to content policy: BLOCKLIST" },
      }),
      502,
      "gemini-4-neon",
    );
    assert.equal(JSON.parse(norm502Gem.body).error.type, "content_policy_violation");

    // 2. 401 kept vs expired & Gemini 400 API_KEY_INVALID via fetch
    const respQueue = [];
    const errFetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl: async () => respQueue.shift(),
    });

    respQueue.push(
      makeJsonResponse({ error: { message: "Authentication failed: upstream 401 UNAUTHENTICATED" } }, 401),
      makeJsonResponse({ error: { code: "invalid_api_key", message: "bad" } }, 401),
      makeJsonResponse({ error: { message: "Invalid API Key" } }, 401),
      new Response("plain unauthorized", { status: 401, headers: { "content-type": "text/plain" } }),
      makeJsonResponse({ error: { code: 400, details: [{ reason: "API_KEY_INVALID" }] } }, 400),
      makeJsonResponse(
        { error: { message: "No available accounts for model gemini-4-argon-high" } },
        429,
        { "retry-after": "33" },
      ),
      makeJsonResponse({ error: { message: "Rate limit exceeded: upstream 429 Too Many Requests" } }, 429),
      makeJsonResponse({ error: { message: "Model gemini-4-argon-high is not in the account catalog" } }, 404),
      makeJsonResponse({ error: { code: "model_not_found", message: "unknown" } }, 404),
    );

    const r401Upstream = await errFetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-oss-120b", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(r401Upstream.status, 401);
    assert.equal(r401Upstream.headers.get("x-magpie-sign-in"), "kept");

    const r401ExpiredCode = await errFetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-oss-120b", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(r401ExpiredCode.headers.get("x-magpie-sign-in"), "expired");

    const r401ExpiredMsg = await errFetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-oss-120b", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(r401ExpiredMsg.headers.get("x-magpie-sign-in"), "expired");

    const r401Plain = await errFetcher("http://localhost/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-oss-120b", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(r401Plain.headers.get("x-magpie-sign-in"), "kept");
    assert.equal(await r401Plain.text(), "plain unauthorized");

    const r400GemKey = await errFetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] }),
    });
    assert.equal(r400GemKey.headers.get("x-magpie-sign-in"), "expired");

    const r429Cool = await errFetcher("http://localhost/v1beta/models/gemini-4-argon:generateContent", {
      method: "POST",
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] }),
    });
    assert.equal(r429Cool.headers.get("retry-after"), "33");
    const j429Cool = await r429Cool.json();
    assert.equal(j429Cool.error.model, "gemini-4-argon");
    assert.equal(hasWholeModelToken(j429Cool.error.message, "gemini-4-argon"), true);

    const r429Up = await errFetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({ model: "claude-opus-5-5", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal((await r429Up.json()).error.model, "claude-opus-5-5");

    const r404Catalog = await errFetcher("http://localhost/v1beta/models/gemini-4-argon:countTokens", {
      method: "POST",
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] }),
    });
    const j404Catalog = await r404Catalog.json();
    assert.equal(j404Catalog.error.model, "gemini-4-argon");
    assert.match(j404Catalog.error.message, /^model gemini-4-argon not found:/);

    // Non-model endpoint 404 is NOT rewritten
    const r404NonModel = await errFetcher("http://localhost/v1/models", { method: "GET" });
    const j404NonModel = await r404NonModel.json();
    assert.equal(j404NonModel.error.message, "unknown");
  });
});

describe("index.mjs plugin entrypoint", () => {
  beforeEach(() => {
    clearAdminSessionCache();
    clearModelCache();
    clearQuotaCache();
    clearPrefixEffortCache();
  });

  it("exposes dual-capability Antigravity2API provider plugin metadata and lifecycle hooks", async () => {
    assert.equal(plugin.id, "magpie-agy2api-plugin");
    assert.equal(
      OFFICIAL_ICON_URL,
      "https://raw.githubusercontent.com/Mag1cFall/Antigravity2API/main/web/src/assets/logo.png",
    );

    const hooks = await plugin.server({
      magpie: {
        options: () => ({
          show_account_details: true,
          refresh_on_usage: false,
          fold_effort_variants: false,
          preserve_cache_effort: true,
        }),
      },
    });

    assert.equal(hooks.provider.id, "agy2api");
    assert.equal(hooks.auth.provider, "agy2api");
    assert.equal(hooks.auth.methods[0].label, "Antigravity2API API Key");

    const promptKeys = hooks.auth.methods[0].prompts.map((p) => p.key);
    assert.deepEqual(promptKeys, ["baseUrl", "adminUsername", "adminPassword"]);
    assert.equal(hooks.auth.methods[0].prompts[0].default, "http://127.0.0.1:8017");
    const foldOpt = hooks.auth.options.find((o) => o.key === "fold_effort_variants");
    assert.equal(foldOpt?.filtersModels, true);

    const cfg = {};
    await hooks.config(cfg);
    assert.equal(cfg.provider.agy2api.name, "Antigravity2API");
    assert.equal(cfg.provider.agy2api.api, "http://127.0.0.1:8017/v1beta");

    const loaded = await hooks.auth.loader(async () => ({
      key: "sk-pub",
      metadata: { baseUrl: "http://127.0.0.1:8017" },
    }));
    assert.equal(loaded.apiKey, "sk-pub");
    assert.equal(loaded.baseURL, "http://127.0.0.1:8017");
    assert.equal(typeof loaded.fetch, "function");
  });

  it("enforces live UI option priority over static options and resolves baseUrl from account > provider.api > default", async () => {
    let uiOpts = { fold_effort_variants: true, show_account_details: false };
    const origFetch = globalThis.fetch;
    const requestedUrls = [];
    const seenHeaders = [];
    globalThis.fetch = async (url, init) => {
      requestedUrls.push(String(url));
      seenHeaders.push(new Headers(init?.headers));
      const pathname = new URL(url).pathname;
      if (pathname.endsWith("/api/models")) {
        return makeJsonResponse({
          models: [
            {
              id: "gemini-fixture",
              name: "Gemini Fixture",
              provider: "MODEL_PROVIDER_GOOGLE",
              quota_group: "gemini",
              thinking_levels: ["low", "high"],
            },
          ],
        });
      }
      if (pathname.endsWith("/api/accounts")) {
        return makeJsonResponse({
          accounts: [
            {
              id: "alice@example.com",
              label: "Alice",
              state: "ready",
              tier: "free-tier",
              quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.9 }],
            },
          ],
        });
      }
      if (pathname.endsWith("/v1/chat/completions")) {
        return makeJsonResponse({ ok: true });
      }
      throw new Error(`Unexpected URL ${url}`);
    };

    try {
      const hooks = await plugin.server(
        {
          magpie: {
            options: () => uiOpts,
          },
        },
        {
          disablePageService: true,
          foldEffortVariants: false,
          showAccountDetails: true,
          refreshOnUsage: false,
        },
      );

      // config with explicit provider.api subpath
      const cfg = {
        provider: {
          agy2api: { api: "https://configured.example.invalid/subpath/v1" },
        },
      };
      await hooks.config(cfg);

      // 1. UI fold_effort_variants: true overrides static false -> only base model
      const m1 = await hooks.provider.models(cfg.provider.agy2api, { auth: { key: "sk-cfg" } });
      assert.ok(m1["gemini-fixture"]);
      assert.equal(m1["gemini-fixture-low"], undefined);
      assert.ok(requestedUrls.some((u) => u === "https://configured.example.invalid/subpath/api/models"));

      // 2. UI switches fold_effort_variants to false -> synthetic suffixes appear
      uiOpts = { fold_effort_variants: false, show_account_details: false };
      const m2 = await hooks.provider.models(cfg.provider.agy2api, { auth: { key: "sk-cfg" } });
      assert.ok(m2["gemini-fixture-low"]);
      assert.ok(m2["gemini-fixture-high"]);

      // 3. Invalid UI string falls back to static true
      uiOpts = { fold_effort_variants: "invalid-bool", show_account_details: false };
      const hooksStaticTrue = await plugin.server(
        { magpie: { options: () => uiOpts } },
        { disablePageService: true, foldEffortVariants: true, refreshOnUsage: false },
      );
      await hooksStaticTrue.config(cfg);
      const m3 = await hooksStaticTrue.provider.models(cfg.provider.agy2api, { auth: { key: "sk-cfg" } });
      assert.equal(m3["gemini-fixture-low"], undefined);

      // 4. UI show_account_details: false overrides static true -> no account rows in usage
      const usage = await hooks.auth.usage(
        async () => ({ key: "sk-cfg" }),
        { ...cfg.provider.agy2api, models: m2 },
      );
      assert.equal(
        usage.windows.some((w) => w.name.includes("Alice")),
        false,
      );
      assert.ok(requestedUrls.some((u) => u === "https://configured.example.invalid/subpath/api/accounts"));

      // 5. chat.headers sets x-agy2api-cache-session for agy2api only, and loader fetch strips it and uses /subpath
      const chatOut = { headers: {} };
      await hooks["chat.headers"](
        { model: { providerID: "agy2api" }, sessionID: "sess-abc" },
        chatOut,
      );
      assert.match(chatOut.headers["x-agy2api-cache-session"], /^[0-9a-f]{64}$/);

      const otherOut = { headers: {} };
      await hooks["chat.headers"](
        { model: { providerID: "other-provider" }, sessionID: "sess-abc" },
        otherOut,
      );
      assert.equal(otherOut.headers["x-agy2api-cache-session"], undefined);

      let dynamicKey = "sk-dynamic-1";
      const loaded = await hooks.auth.loader(
        async () => ({ key: dynamicKey }),
        cfg.provider.agy2api,
      );
      assert.equal(loaded.baseURL, "https://configured.example.invalid/subpath");
      await loaded.fetch("https://configured.example.invalid/subpath/chat/completions", {
        method: "POST",
        headers: chatOut.headers,
        body: JSON.stringify({ model: "gpt-oss", messages: [{ role: "user", content: "hi" }] }),
      });
      const lastUrl = requestedUrls[requestedUrls.length - 1];
      const lastHdrs = seenHeaders[seenHeaders.length - 1];
      assert.equal(lastUrl, "https://configured.example.invalid/subpath/v1/chat/completions");
      assert.equal(lastHdrs.get("x-agy2api-cache-session"), null);
      assert.equal(lastHdrs.get("authorization"), "Bearer sk-dynamic-1");

      // 6. Clearing key in getAuth snapshot must NOT resurrect old key
      dynamicKey = "";
      await loaded.fetch("https://configured.example.invalid/subpath/chat/completions", {
        method: "POST",
        body: JSON.stringify({ model: "gpt-oss", messages: [{ role: "user", content: "hi" }] }),
      });
      assert.equal(seenHeaders[seenHeaders.length - 1].get("authorization"), null);

      // 7. Explicit account baseUrl overrides provider.api (even when set to loopback)
      const overrideLoaded = await hooks.auth.loader(
        async () => ({
          key: "sk-acct",
          metadata: { baseUrl: "http://127.0.0.1:8017" },
        }),
        cfg.provider.agy2api,
      );
      assert.equal(overrideLoaded.baseURL, "http://127.0.0.1:8017");
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("ignores non-primitive option objects, avoids hanging on root options() during inference, prefers snake_case across UI sources, and guards null output in chat.headers", async () => {
    const sentBodies = [];
    const origFetch = globalThis.fetch;
    globalThis.fetch = async (_url, init) => {
      sentBodies.push(JSON.parse(init.body));
      return makeJsonResponse({ ok: true });
    };

    try {
      // 1. cache_ttl_sec: { valueOf: null, toString: null } + hung root options() while options("agy2api") returns preserve_cache_effort
      const hooks = await plugin.server(
        {
          magpie: {
            options: (ns) => {
              if (ns === "agy2api") {
                return {
                  preserve_cache_effort: true,
                  cache_ttl_sec: { valueOf: null, toString: null },
                };
              }
              return new Promise(() => {}); // never resolves!
            },
          },
        },
        { disablePageService: true },
      );

      // chat.headers null output does not throw
      await hooks["chat.headers"]({ model: { providerID: "agy2api" }, sessionID: "s1" }, null);

      const loaded = await hooks.auth.loader(async () => ({
        key: "sk-pub",
        metadata: { baseUrl: "https://opts-safe.example.invalid" },
      }));
      await loaded.fetch("https://opts-safe.example.invalid/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({ model: "gpt-oss", messages: [{ role: "user", content: "hi" }] }),
      });
      assert.equal(sentBodies.length, 1);

      // 2. Priority by key across UI sources: root snake_case beats namespace camelCase!
      const hooksPriority = await plugin.server(
        {
          magpie: {
            options: (ns) =>
              ns === "agy2api"
                ? { foldEffortVariants: false }
                : { fold_effort_variants: true },
          },
        },
        { disablePageService: true, foldEffortVariants: false },
      );

      globalThis.fetch = async (url) => {
        if (String(url).endsWith("/api/models")) {
          return makeJsonResponse({
            models: [
              {
                id: "gemini-prio",
                provider: "MODEL_PROVIDER_GOOGLE",
                thinking_levels: ["low", "high"],
              },
            ],
          });
        }
        throw new Error(`Unexpected ${url}`);
      };
      const models = await hooksPriority.provider.models(
        {},
        { auth: { key: "sk-pub", metadata: { baseUrl: "https://opts-prio.example.invalid" } } },
      );
      assert.ok(models["gemini-prio"]);
      assert.equal(models["gemini-prio-low"], undefined);

      // 3. Hot-reloadable preserve_cache_effort: starts false (no rewrite/warm), then dynamically flips true without recreating loader
      let optionReads = 0;
      let slowOptValue = false;
      const slowBodies = [];
      globalThis.fetch = async (_url, init) => {
        slowBodies.push(JSON.parse(init.body));
        return makeJsonResponse({ ok: true });
      };
      const hooksSlow = await plugin.server(
        {
          magpie: {
            options: async () => {
              optionReads++;
              await new Promise((r) => setTimeout(r, 18));
              return { preserve_cache_effort: slowOptValue };
            },
          },
        },
        { disablePageService: true },
      );
      const slowLoaded = await hooksSlow.auth.loader(async () => ({
        key: "sk-slow",
        metadata: { baseUrl: "https://slow-opts.example.invalid" },
      }));
      const bigPad = "p".repeat(36 * 1024);
      await slowLoaded.fetch("https://slow-opts.example.invalid/v1/chat/completions", {
        method: "POST",
        headers: { "x-session-id": "slow-sess" },
        body: JSON.stringify({
          model: "gpt-oss",
          reasoning_effort: "high",
          max_completion_tokens: 32000,
          messages: [{ role: "user", content: bigPad }],
        }),
      });
      await slowLoaded.fetch("https://slow-opts.example.invalid/v1/chat/completions", {
        method: "POST",
        headers: { "x-session-id": "slow-sess" },
        body: JSON.stringify({
          model: "gpt-oss",
          reasoning_effort: "low",
          max_completion_tokens: 2048,
          messages: [{ role: "user", content: bigPad }, { role: "user", content: "aux" }],
        }),
      });
      assert.equal(optionReads, 2);
      assert.equal(slowBodies[1].reasoning_effort, "low");

      slowOptValue = true;
      await slowLoaded.fetch("https://slow-opts.example.invalid/v1/chat/completions", {
        method: "POST",
        headers: { "x-session-id": "slow-sess" },
        body: JSON.stringify({
          model: "gpt-oss",
          reasoning_effort: "high",
          max_completion_tokens: 32000,
          messages: [{ role: "user", content: bigPad }],
        }),
      });
      await slowLoaded.fetch("https://slow-opts.example.invalid/v1/chat/completions", {
        method: "POST",
        headers: { "x-session-id": "slow-sess" },
        body: JSON.stringify({
          model: "gpt-oss",
          reasoning_effort: "low",
          max_completion_tokens: 2048,
          messages: [{ role: "user", content: bigPad }, { role: "user", content: "aux" }],
        }),
      });
      assert.equal(optionReads, 4);
      assert.equal(slowBodies[3].reasoning_effort, "high");

      // 4. Cold-start usage() (before provider.models) triggers ensureModelsDiscovered and passes apiKey
      clearModelCache();
      clearQuotaCache();
      const coldUrls = [];
      globalThis.fetch = async (url) => {
        const p = new URL(url).pathname;
        coldUrls.push(p);
        if (p === "/api/models") {
          return makeJsonResponse({
            models: [
              {
                id: "gemini-cold",
                name: "Gemini Cold",
                provider: "MODEL_PROVIDER_GOOGLE",
                quota_group: "gemini",
              },
              {
                id: "my-cold",
                name: "My Cold Alias",
                provider: "MODEL_PROVIDER_GOOGLE",
              },
            ],
          });
        }
        if (p === "/api/settings") {
          return makeJsonResponse({
            values: {
              API_KEYS: "sk-cold",
              API_KEY_ACCOUNTS: "sk-cold:Cold-Acc",
              MODEL_MAPPING: "my-cold:gemini-cold",
              QUOTA_RESERVE_PERCENT: "0",
            },
            admin_password_set: true,
          });
        }
        if (p === "/api/accounts/refresh") {
          return makeJsonResponse({
            accounts: [
              {
                id: "Cold-Acc",
                state: "ready",
                tier: "free-tier",
                quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.7 }],
              },
              {
                id: "cold-acc",
                state: "ready",
                tier: "g1-pro-tier",
                quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.1 }],
              },
              {
                id: "other-acc",
                state: "ready",
                tier: "g1-ultra-tier",
                quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 1.0 }],
              },
            ],
            failed: {},
          });
        }
        if (p === "/api/accounts") {
          return makeJsonResponse({
            accounts: [
              {
                id: "Cold-Acc",
                state: "ready",
                tier: "free-tier",
                quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.7 }],
              },
              {
                id: "cold-acc",
                state: "ready",
                tier: "g1-pro-tier",
                quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.1 }],
              },
              {
                id: "other-acc",
                state: "ready",
                tier: "g1-ultra-tier",
                quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 1.0 }],
              },
            ],
          });
        }
        throw new Error(`Unexpected ${url}`);
      };
      const coldUsage = await hooksSlow.auth.usage(async () => ({
        key: "sk-cold",
        metadata: { baseUrl: "https://cold-usage.example.invalid" },
      }));
      assert.ok(coldUrls.includes("/api/models"));
      assert.equal(coldUsage.plan, "FREE ×1");
      assert.equal(coldUsage.windows.find((w) => !w.aside && w.model === "gemini-cold")?.used, 30);
      assert.equal(coldUsage.windows.find((w) => !w.aside && w.model === "my-cold")?.used, 30);

      // chat.headers also supports agy2api-plugin
      const pluginHdrOut = { headers: {} };
      await hooksSlow["chat.headers"](
        { model: { providerID: "agy2api-plugin" }, sessionID: "sess-p" },
        pluginHdrOut,
      );
      assert.match(pluginHdrOut.headers["x-agy2api-cache-session"], /^[0-9a-f]{64}$/);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});
