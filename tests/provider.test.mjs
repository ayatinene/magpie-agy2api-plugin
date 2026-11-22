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
  getAgy2ApiUsage,
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
});

describe("models.mjs", () => {
  beforeEach(() => {
    clearAdminSessionCache();
    clearModelCache();
  });

  it("discovers models dynamically from GET /api/models with cookie auth and expands thinking_levels by default", async () => {
    const fetchImpl = async (url) => {
      if (url.endsWith("/api/session")) {
        return new Response("{}", {
          status: 200,
          headers: { "set-cookie": "antigravity_admin=sess1; Path=/api" },
        });
      }
      if (url.endsWith("/api/models")) {
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
            baseUrl: "http://127.0.0.1:8017",
            adminUsername: "admin",
            adminPassword: "pw",
          },
        },
      },
      { fetchImpl, foldEffortVariants: false },
    );

    // Base models + expanded effort models
    assert.ok(models["gemini-4-neon"]);
    assert.deepEqual(Object.keys(models["gemini-4-neon"].variants), [
      "low",
      "medium",
      "high",
      "xhigh",
    ]);
    assert.equal(models["gemini-4-neon"].api.npm, "@ai-sdk/google");
    assert.equal(models["gemini-4-neon"].api.url, "http://127.0.0.1:8017/v1beta");
    assert.equal(models["gemini-4-neon"].providerID, "agy2api");
    assert.equal(models["gemini-4-neon"].capabilities.input.video, true);
    assert.equal(models["gemini-4-neon"].capabilities.input.image, true);

    assert.ok(models["gemini-4-neon-low"]);
    assert.ok(models["gemini-4-neon-xhigh"]);
    assert.equal(models["gemini-4-neon-xhigh"].name, "Gemini 4 Neon (XHigh)");
    assert.deepEqual(models["gemini-4-neon-xhigh"].variants, {});

    assert.equal(models["claude-opus-5-5"].api.npm, "@ai-sdk/anthropic");
    assert.equal(models["claude-opus-5-5"].api.url, "http://127.0.0.1:8017/v1");
    assert.ok(models["claude-opus-5-5-low"]);
    assert.ok(models["claude-opus-5-5-high"]);

    assert.equal(models["gpt-oss-120b"].api.npm, "@ai-sdk/openai-compatible");
    assert.equal(models["gpt-oss-120b"].api.url, "http://127.0.0.1:8017/v1");
    assert.ok(models["custom-future-argon"]);

    assert.equal(isXhighGeminiModel("http://127.0.0.1:8017", "gemini-4-neon"), true);
    assert.equal(isXhighGeminiModel("http://127.0.0.1:8017", "claude-opus-5-5"), false);

    const qgMap = getModelQuotaGroupMap("http://127.0.0.1:8017");
    assert.equal(qgMap.get("gemini-4-neon"), "gemini");
    assert.equal(qgMap.get("gemini-4-neon-xhigh"), "gemini");
    assert.equal(qgMap.get("claude-opus-5-5-low"), "3p");
    assert.equal(qgMap.get("custom-future-argon"), "gemini-argon-wtu");

    // Switching to fold_effort_variants = true hides suffixed models
    const folded = getDiscoveredModels("http://127.0.0.1:8017", { foldEffortVariants: true });
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

  it("handles pre-suffixed entries seamlessly in both folded and unfolded modes", () => {
    const raw = new Map([
      ["gemini-4-flash-low", { id: "gemini-4-flash-low", provider: "MODEL_PROVIDER_GOOGLE", quota_group: "gemini" }],
      ["gemini-4-flash-high", { id: "gemini-4-flash-high", provider: "MODEL_PROVIDER_GOOGLE", quota_group: "gemini" }],
    ]);
    const unfolded = buildModelsFromRawEntries(raw, DEFAULT_BASE_URL, { foldEffortVariants: false });
    assert.ok(unfolded.models["gemini-4-flash-low"]);
    assert.ok(unfolded.models["gemini-4-flash-high"]);
    assert.equal(unfolded.modelQuotaGroupMap.get("gemini-4-flash-low"), "gemini");

    const folded = buildModelsFromRawEntries(raw, DEFAULT_BASE_URL, { foldEffortVariants: true });
    assert.ok(folded.models["gemini-4-flash"]);
    assert.deepEqual(Object.keys(folded.models["gemini-4-flash"].variants), ["low", "high"]);
    assert.equal(folded.models["gemini-4-flash-low"], undefined);
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

    // Gemini pool on cooling account is 80% remaining -> 20% used
    const geminiWin = usage.windows.find((w) => !w.aside && w.model === "gemini-4-neon");
    assert.equal(geminiWin.used, 20);
    assert.equal(geminiWin.pool, "Gemini");

    // Expanded effort model also gets routing window
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
    assert.equal(q.mappedFromGemini, true);
    assert.equal(q.inCooldown, true);
    assert.equal(q.effectiveRem, 0);
    assert.equal(q.h5, 70);
    assert.equal(q.weekly, 90);
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

    // Expected weighted remaining:
    // Component 1 (Alice+Bob): weight=2.0, effectiveRem=50
    // Component 2 (Carol+Dave): weight=1.5, effectiveRem=90 (min(100,90))
    // Component 3 (Erin): weight=1.0, effectiveRem=100
    // Total = (2.0*50 + 1.5*90 + 1.0*100) / (2.0 + 1.5 + 1.0) = (100 + 135 + 100) / 4.5 = 335 / 4.5 = 74.44% -> 74% rem -> 26% used
    const usage = computeAgy2ApiUsage(accounts, {
      discoveredModels: {
        "gemini-4-neon": { id: "gemini-4-neon", name: "Gemini 4 Neon", family: "Gemini" },
      },
      modelQuotaGroupMap: new Map([["gemini-4-neon", "gemini"]]),
      nowMs,
    });

    const geminiWin = usage.windows.find((w) => !w.aside && w.model === "gemini-4-neon");
    assert.equal(geminiWin.used, 26);

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
    const unknownRow = usage.windows.find((w) => w.aside && w.pool === "Gemini");
    assert.equal(unknownRow.display, "未知");
    assert.equal(unknownRow.used, undefined);
  });

  it("caches accounts, debounces refresh, and distinguishes stale cache from live error", async () => {
    let now = Date.parse("2026-11-22T15:00:00Z");
    let refreshCalls = 0;
    let accountCalls = 0;
    let shouldFailAccounts = false;

    const fetchImpl = async (url) => {
      if (url.endsWith("/api/session")) {
        return new Response("{}", {
          status: 200,
          headers: { "set-cookie": "antigravity_admin=tok-q; Path=/api" },
        });
      }
      if (url.endsWith("/api/accounts/refresh")) {
        refreshCalls++;
        return makeJsonResponse({ ok: true });
      }
      if (url.endsWith("/api/accounts")) {
        accountCalls++;
        if (shouldFailAccounts) {
          return makeJsonResponse({ error: "internal error" }, 500);
        }
        return makeJsonResponse({
          accounts: [
            {
              id: "alice@example.com",
              state: "ready",
              tier: "g1-pro-tier",
              quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.8 }],
              quota_at: "2026-11-22T14:59:00Z",
            },
          ],
        });
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

    // 1. First call fetches refresh + accounts
    const u1 = await getAgy2ApiUsage(opts);
    assert.equal(refreshCalls, 1);
    assert.equal(accountCalls, 1);
    assert.equal(u1.plan, "PRO ×1");

    // 2. Within 10s cache TTL -> served from cache without network
    now += 5_000;
    const u2 = await getAgy2ApiUsage(opts);
    assert.equal(refreshCalls, 1);
    assert.equal(accountCalls, 1);
    assert.equal(u2.plan, "PRO ×1");

    // 3. Past 10s cache TTL but within 60s refresh cooldown -> fetches accounts, skips refresh; fails -> stale warning!
    now += 10_000;
    shouldFailAccounts = true;
    const u3 = await getAgy2ApiUsage(opts);
    assert.equal(refreshCalls, 1);
    assert.equal(accountCalls, 2);
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
});

describe("fetch.mjs", () => {
  beforeEach(() => {
    clearAdminSessionCache();
    clearModelCache();
    clearPrefixEffortCache();
  });

  it("rewrites URLs and sets auth headers for all 4 protocols while stripping x-magpie-effort", async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url, headers: new Headers(init.headers), body: init.body });
      return makeJsonResponse({ ok: true });
    };

    const fetcher = createAgy2ApiFetch({
      baseUrl: "http://127.0.0.1:8017/v1/",
      apiKey: "sk-pub-key",
      fetchImpl,
    });

    await fetcher("https://example.invalid/models/gemini-4-neon:generateContent", {
      method: "POST",
      headers: { "x-magpie-effort": "high", "x-api-key": "stale" },
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] }),
    });
    assert.equal(calls[0].url, "http://127.0.0.1:8017/v1beta/models/gemini-4-neon:generateContent");
    assert.equal(calls[0].headers.get("x-goog-api-key"), "sk-pub-key");
    assert.equal(calls[0].headers.get("authorization"), "Bearer sk-pub-key");
    assert.equal(calls[0].headers.get("x-api-key"), null);
    assert.equal(calls[0].headers.get("x-magpie-effort"), null);

    await fetcher("https://example.invalid/v1/messages", {
      method: "POST",
      headers: { "x-goog-api-key": "stale" },
      body: JSON.stringify({ model: "claude-opus-5-5", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(calls[1].url, "http://127.0.0.1:8017/v1/messages");
    assert.equal(calls[1].headers.get("x-api-key"), "sk-pub-key");
    assert.equal(calls[1].headers.get("x-goog-api-key"), null);

    await fetcher("https://example.invalid/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-oss-120b", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(calls[2].url, "http://127.0.0.1:8017/v1/chat/completions");
    assert.equal(calls[2].headers.get("authorization"), "Bearer sk-pub-key");

    await fetcher("https://example.invalid/v1/responses", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-oss-120b", input: "hi" }),
    });
    assert.equal(calls[3].url, "http://127.0.0.1:8017/v1/responses");
    assert.equal(calls[3].headers.get("authorization"), "Bearer sk-pub-key");

    assert.equal(detectProtocol("/v1/chat/completions"), "chat");
    assert.equal(detectProtocol("/v1/responses"), "responses");
    assert.equal(detectProtocol("/v1/messages"), "anthropic");
    assert.equal(detectProtocol("/v1beta/models/gemini-4-neon:streamGenerateContent"), "gemini");
    assert.equal(
      rewriteUpstreamUrl("http://x/v1/responses?stream=true", "http://127.0.0.1:8017").url,
      "http://127.0.0.1:8017/v1/responses?stream=true",
    );
  });

  it("passes xhigh through only for xhigh-capable Gemini models", async () => {
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
      includeThoughts: true,
      thinkingLevel: "xhigh",
    });

    await fetcher("http://localhost/v1beta/models/gemini-3-flash:generateContent", {
      method: "POST",
      headers: { "x-magpie-effort": "xhigh" },
      body: JSON.stringify({
        generationConfig: { thinkingConfig: { thinkingLevel: "high" } },
        contents: [{ role: "user", parts: [{ text: "hi" }] }],
      }),
    });

    // gemini-3-flash does not support xhigh -> left at "high"
    assert.equal(sentBodies[1].generationConfig.thinkingConfig.thinkingLevel, "high");
  });

  it("preserves warm cache effort on auxiliary downgrades across all 4 protocols (gemini, anthropic, chat, responses)", async () => {
    const sent = [];
    let preserveOpt = true;
    const fetchImpl = async (url, init) => {
      sent.push({ url, body: JSON.parse(init.body) });
      return makeJsonResponse({ ok: true });
    };

    const fetcher = createAgy2ApiFetch({
      baseUrl: DEFAULT_BASE_URL,
      apiKey: "sk-pub",
      fetchImpl,
      cacheAffinityMinBodyBytes: 128,
      getOptions: () => ({ preserveCacheEffort: preserveOpt }),
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

    // 3. Anthropic (/v1/messages)
    await fetcher("http://localhost/v1/messages", {
      method: "POST",
      body: JSON.stringify({
        model: "claude-opus-5-5",
        system: "sys-anth",
        max_tokens: 32000,
        thinking: { type: "enabled", budget_tokens: 16384 },
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
    assert.deepEqual(sent[5].body.thinking, { type: "enabled", budget_tokens: 16384 });
    assert.ok(sent[5].body.max_tokens > 16384);

    // 4. Gemini (/v1beta/models/...)
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: "sys-gem" }] },
        generationConfig: { maxOutputTokens: 32000, thinkingConfig: { thinkingLevel: "high" } },
        contents: [{ role: "user", parts: [{ text: bigText }] }],
      }),
    });
    await fetcher("http://localhost/v1beta/models/gemini-4-neon:generateContent", {
      method: "POST",
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: "sys-gem" }] },
        generationConfig: { maxOutputTokens: 1024, thinkingConfig: { thinkingLevel: "low" } },
        contents: [
          { role: "user", parts: [{ text: bigText }] },
          { role: "model", parts: [{ text: "ok" }] },
        ],
      }),
    });
    assert.equal(sent[7].body.generationConfig.thinkingConfig.thinkingLevel, "high");

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
    assert.equal(sent[8].body.reasoning_effort, "low");

    // Live option preserve_cache_effort = false disables restoration
    preserveOpt = false;
    await fetcher("http://localhost/v1/chat/completions", {
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
    assert.equal(sent[9].body.reasoning_effort, "low");
  });

  it("normalizes 429, 503/529, and 400 content rejection with strict semantic matching", async () => {
    assert.equal(hasWholeModelToken("quota exceeded for gemini-4-argon-medium", "gemini-4-argon"), false);
    assert.equal(hasWholeModelToken("model gemini-4-argon: quota exceeded", "gemini-4-argon"), true);

    // 429 prefix collision test: body mentions gemini-4-argon-medium while routed model is gemini-4-argon
    const norm429 = normalizeUpstreamErrorResponse(
      JSON.stringify({ error: { message: "Quota exhausted for gemini-4-argon-medium" } }),
      429,
      "gemini-4-argon",
    );
    const body429 = JSON.parse(norm429.body);
    assert.equal(hasWholeModelToken(body429.error.message, "gemini-4-argon"), true);
    assert.match(body429.error.message, /RESOURCE_EXHAUSTED/);
    assert.equal(body429.error.status, "RESOURCE_EXHAUSTED");

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

    // 503 explicit model overload / 529 -> preserves overload semantics + routedModel
    const norm503 = normalizeUpstreamErrorResponse(
      JSON.stringify({ error: { message: "MODEL_CAPACITY_EXHAUSTED" } }),
      503,
      "gemini-4-neon",
    );
    const body503 = JSON.parse(norm503.body);
    assert.equal(body503.error.type, "overloaded_error");
    assert.match(body503.error.message, /gemini-4-neon/);
    assert.match(body503.error.message, /overloaded/i);

    const norm529 = normalizeUpstreamErrorResponse(
      JSON.stringify({ error: { message: "Overloaded" } }),
      529,
      "claude-opus-5-5",
    );
    const body529 = JSON.parse(norm529.body);
    assert.equal(body529.error.type, "overloaded_error");
    assert.equal(hasWholeModelToken(body529.error.message, "claude-opus-5-5"), true);

    // 400 OpenAI content rejection
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
    assert.match(oai400.error.message, /flagged/i);

    // 400 Anthropic content rejection
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

  it("preserves real HTTP status and Retry-After header through createAgy2ApiFetch", async () => {
    const fetchImpl = async () =>
      new Response(JSON.stringify({ error: { message: "MODEL_CAPACITY_EXHAUSTED" } }), {
        status: 503,
        headers: { "retry-after": "12", "x-ratelimit-remaining": "0" },
      });

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
    assert.equal(json.error.type, "overloaded_error");
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
});
