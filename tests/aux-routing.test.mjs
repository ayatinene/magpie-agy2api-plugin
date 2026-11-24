import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { onRequest as hookOnRequest, onResponse as hookOnResponse } from "../hooks.mjs";
import { onRequest as mwOnRequest } from "../middleware.mjs";
import {
  RELAY_FIELD,
  RELAY_TTL_MS,
  hmacSha256Hex,
  sha256Hex,
  signRelayPayload,
  timingSafeEqualHex,
  verifyRelayPayload,
} from "../lib/relay-crypto.mjs";
import { RELAY_SECRET } from "../lib/relay-secret.mjs";
import {
  classifyRequestRole,
  clearAuxRouterState,
  clearAuxRoutingDiagnostics,
  clearCustomAuxAdapters,
  ensureRelaySecret,
  evaluatePrefixCompatibility,
  extractConversationSnapshot,
  getAuxRoutingDiagnostics,
  getMainSessionState,
  getRegisteredAuthScope,
  registerAuthScope,
  registerAuxAdapter,
  setPluginRuntimeContext,
  validateCrossModelSwitch,
} from "../lib/aux-router.mjs";
import { createAgy2ApiFetch, clearPrefixEffortCache } from "../lib/fetch.mjs";
import { clearModelCache, ensureModelsDiscovered } from "../lib/models.mjs";
import { clearQuotaCache, fetchAccountsCached } from "../lib/quota.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.resolve(__dirname, "..");

const TEST_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const BIG_PAD = "X".repeat(36 * 1024);

function resetAllState() {
  clearPrefixEffortCache();
  clearAuxRouterState();
  clearAuxRoutingDiagnostics();
  clearCustomAuxAdapters();
  clearModelCache();
  clearQuotaCache();
  setPluginRuntimeContext({ directory: "", magpie: null, staticOptions: null, authScope: null });
}

async function seedCatalog(models, accounts = null, baseUrl = "http://127.0.0.1:8017") {
  const mockFetch = async (url) => {
    const u = String(url);
    if (u.endsWith("/api/models")) {
      return new Response(JSON.stringify({ models }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (u.endsWith("/api/settings")) {
      return new Response(JSON.stringify({ values: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (u.endsWith("/api/accounts") && accounts) {
      return new Response(JSON.stringify({ accounts }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`Unexpected seed fetch: ${u}`);
  };
  await ensureModelsDiscovered(baseUrl, "sk-test", { fetchImpl: mockFetch });
  if (accounts) {
    await fetchAccountsCached(baseUrl, {
      apiKey: "sk-test",
      refreshOnUsage: false,
      fetchImpl: mockFetch,
    });
  }
}

describe("Phase 2: Pure JS Crypto & Relay Security", () => {
  it("matches node:crypto SHA-256 and HMAC-SHA256 byte-for-byte across ASCII, CJK, emoji, and long keys", () => {
    const samples = [
      "",
      "hello world",
      "测试中文字符与特殊符号\0\n\t",
      "Astral emoji 🚀🔥🧪 surrogate boundary",
      "A".repeat(200),
    ];
    for (const s of samples) {
      const expectedSha = crypto.createHash("sha256").update(s, "utf8").digest("hex");
      assert.equal(sha256Hex(s), expectedSha);

      for (const k of ["short", TEST_SECRET, "K".repeat(140)]) {
        const expectedHmac = crypto.createHmac("sha256", k).update(s, "utf8").digest("hex");
        assert.equal(hmacSha256Hex(k, s), expectedHmac);
      }
    }

    assert.equal(timingSafeEqualHex("abcd", "abcd"), true);
    assert.equal(timingSafeEqualHex("abcd", "abce"), false);
    assert.equal(timingSafeEqualHex("abcd", "abc"), false);
    assert.equal(timingSafeEqualHex("", ""), false);
  });

  it("keeps repo lib/relay-secret.mjs as empty placeholder and auto-generates only in non-.git temp dirs", () => {
    assert.equal(RELAY_SECRET, "");

    // Calling against repo root (contains .git) MUST NOT write a secret
    assert.equal(ensureRelaySecret({ targetDir: PLUGIN_ROOT }), "");
    assert.match(
      fs.readFileSync(path.join(PLUGIN_ROOT, "lib", "relay-secret.mjs"), "utf8"),
      /export const RELAY_SECRET = "";/,
    );

    // Calling against a non-.git temp copy generates 64-hex secret and touches middleware.mjs
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agy2api-relay-test-"));
    try {
      fs.mkdirSync(path.join(tmpDir, "lib"), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, "lib", "relay-secret.mjs"), 'export const RELAY_SECRET = "";\n');
      fs.writeFileSync(path.join(tmpDir, "middleware.mjs"), "// placeholder\n");
      const oldTime = new Date(Date.now() - 60_000);
      fs.utimesSync(path.join(tmpDir, "middleware.mjs"), oldTime, oldTime);

      const secret = ensureRelaySecret({ targetDir: tmpDir });
      assert.match(secret, /^[0-9a-f]{64}$/);
      const written = fs.readFileSync(path.join(tmpDir, "lib", "relay-secret.mjs"), "utf8");
      assert.ok(written.includes(secret));
      const statAfter = fs.statSync(path.join(tmpDir, "middleware.mjs"));
      assert.ok(statAfter.mtimeMs > oldTime.getTime());

      // Second call reuses the persisted secret
      assert.equal(ensureRelaySecret({ targetDir: tmpDir }), secret);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("strips forged, expired, cross-protocol, and malformed _agy2api_relay across hooks.mjs, middleware.mjs, and fetch.mjs", async () => {
    resetAllState();
    const baseBody = {
      model: "claude-opus-5-5",
      max_tokens: 4096,
      messages: [{ role: "user", content: "hi" }],
    };

    // 1. Missing / wrong signature / expired / cross-protocol in middleware.onRequest
    const unsigned = mwOnRequest(
      { ...baseBody, [RELAY_FIELD]: { v: 1, toModel: "agy2api/evil", proto: "anthropic", ts: Date.now(), nonce: "n1", sig: "0".repeat(64) } },
      { protocol: "anthropic", options: { relaySecret: TEST_SECRET } },
    );
    assert.equal(RELAY_FIELD in unsigned, false);
    assert.equal(unsigned.model, "claude-opus-5-5");

    const now = Date.now();
    const expiredRelay = signRelayPayload(TEST_SECRET, {
      toModel: "agy2api/gemini-3.8-flash",
      toEffort: "low",
      proto: "anthropic",
      ts: now - RELAY_TTL_MS - 5000,
      nonce: "n2",
    });
    const expRes = mwOnRequest(
      { ...baseBody, [RELAY_FIELD]: expiredRelay },
      { protocol: "anthropic", options: { relaySecret: TEST_SECRET } },
    );
    assert.equal(RELAY_FIELD in expRes, false);
    assert.equal(expRes.model, "claude-opus-5-5");

    const crossProtoRelay = signRelayPayload(TEST_SECRET, {
      toModel: "agy2api/gemini-3.8-flash",
      toEffort: "low",
      proto: "chat",
      ts: now,
      nonce: "n3",
    });
    const crossRes = mwOnRequest(
      { ...baseBody, [RELAY_FIELD]: crossProtoRelay },
      { protocol: "anthropic", options: { relaySecret: TEST_SECRET } },
    );
    assert.equal(RELAY_FIELD in crossRes, false);
    assert.equal(crossRes.model, "claude-opus-5-5");

    // Verify helper checks
    assert.equal(verifyRelayPayload(TEST_SECRET, crossProtoRelay, "anthropic", now).valid, false);
    assert.equal(verifyRelayPayload(TEST_SECRET, crossProtoRelay, "chat", now).valid, true);

    // 2. Valid signature rewrites model and effort cleanly without mutating caller input
    const validRelay = signRelayPayload(TEST_SECRET, {
      toModel: "agy2api/gemini-3.8-flash",
      toEffort: "low",
      proto: "anthropic",
      ts: now,
      nonce: "n4",
    });
    const inputWithRelay = { ...baseBody, output_config: { effort: "high" }, [RELAY_FIELD]: validRelay };
    const rewritten = mwOnRequest(inputWithRelay, {
      protocol: "anthropic",
      options: { relaySecret: TEST_SECRET },
    });
    assert.equal(RELAY_FIELD in rewritten, false);
    assert.equal(rewritten.model, "agy2api/gemini-3.8-flash");
    assert.equal(rewritten.output_config.effort, "low");
    assert.equal(RELAY_FIELD in inputWithRelay, true, "caller object must not be mutated");

    // 3. hooks.onRequest strips forged _agy2api_relay even on /backend-api/* or missing session
    const hookStrippedBackend = await hookOnRequest(
      { ...baseBody, [RELAY_FIELD]: validRelay },
      { protocol: "anthropic", path: "/backend-api/codex/responses", session: "s1", options: { relaySecret: TEST_SECRET } },
    );
    assert.equal(RELAY_FIELD in hookStrippedBackend, false);
    assert.equal(hookStrippedBackend.model, "claude-opus-5-5");

    const hookStrippedNoSess = await hookOnRequest(
      { ...baseBody, [RELAY_FIELD]: validRelay },
      { protocol: "anthropic", path: "/v1/messages", session: "", options: { relaySecret: TEST_SECRET } },
    );
    assert.equal(RELAY_FIELD in hookStrippedNoSess, false);

    // 4. fetch.mjs fallback strips residual _agy2api_relay
    const sent = [];
    const agyFetch = createAgy2ApiFetch({
      baseUrl: "http://127.0.0.1:8017",
      apiKey: "sk-test",
      fetchImpl: async (_url, init) => {
        sent.push(JSON.parse(init.body));
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
    });
    await agyFetch("http://127.0.0.1:8017/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...baseBody, [RELAY_FIELD]: validRelay }),
    });
    assert.equal(RELAY_FIELD in sent[0], false);
  });
});

describe("Phase 2: B1 Classifier & Extensible Adapters", () => {
  beforeEach(resetAllState);

  it("handles explicit purpose/header, subagent exclusion, custom adapters, and prevents small title requests from upgrading", async () => {
    const baseMain = {
      model: "claude-opus-5-5",
      max_tokens: 64000,
      system: `Main system\n${BIG_PAD}`,
      messages: [
        { role: "user", content: "Inspect repository" },
        { role: "assistant", content: "Reading files." },
        { role: "user", content: "Explain routing" },
      ],
      output_config: { effort: "high" },
    };
    const state = {};
    await hookOnRequest(baseMain, {
      protocol: "anthropic",
      session: "sess-b1",
      path: "/v1/messages",
      state,
      options: { relaySecret: TEST_SECRET },
    });
    await hookOnResponse({ content: [{ type: "text", text: "Done." }] }, { success: true, state });
    assert.ok(getMainSessionState("sess-b1"));

    // 1. Subagent exclusion: must NOT classify as aux and must NOT overwrite mainState
    const subState = {};
    const subOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 4096,
        system: `Subagent system\n${BIG_PAD}`,
        messages: [{ role: "user", content: "Subagent search" }],
        output_config: { effort: "low" },
      },
      {
        protocol: "anthropic",
        session: "sess-b1",
        kind: "subagent",
        path: "/v1/messages",
        state: subState,
        options: { relaySecret: TEST_SECRET },
      },
    );
    assert.equal(subOut, undefined);
    await hookOnResponse({ content: [{ type: "text", text: "Sub." }] }, { success: true, state: subState });
    assert.equal(getMainSessionState("sess-b1").effort, "high");

    // 2. Explicit metadata.purpose: main_turn & compact stay main
    const compactCheck = classifyRequestRole({
      body: { metadata: { purpose: "compact" } },
      bodyBytes: 50000,
      protocol: "anthropic",
    });
    assert.equal(compactCheck.role, "main");

    // 3. Small title request (< minBodyBytes, no history lineage) does NOT hit Branch 2 upgrade
    const titleOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 256,
        metadata: { purpose: "title" },
        messages: [{ role: "user", content: "Generate short title" }],
        output_config: { effort: "low" },
      },
      {
        protocol: "anthropic",
        session: "sess-b1",
        path: "/v1/messages",
        options: { relaySecret: TEST_SECRET, auxIncompatiblePolicy: "keep" },
      },
    );
    assert.equal(titleOut, undefined);
    const diags = getAuxRoutingDiagnostics();
    assert.equal(diags.at(-1).compatible, false);

    // 4. Custom extensible adapter
    const unregister = registerAuxAdapter({
      name: "custom_probe",
      classify: (c) => (c.body?.metadata?.customFlag ? { role: "auxiliary", reason: "custom_flag" } : null),
    });
    const customRes = classifyRequestRole({ body: { metadata: { customFlag: true } }, bodyBytes: 100, protocol: "chat" });
    assert.equal(customRes.role, "auxiliary");
    assert.equal(customRes.detector, "custom_probe");
    unregister();
  });

  it("detects ZCode memory extract (stripped <system-reminder>, changed tools, low/disabled effort) and tool-stripped branches while honoring manual UI switches and brand new sessions", async () => {
    // 1. No active main session -> structural heuristic never triggers
    const freshOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 4096,
        system: `System\n${BIG_PAD}`,
        messages: [
          { role: "user", content: "Turn 1" },
          { role: "assistant", content: "Reply 1" },
          { role: "user", content: "Extract memories" },
        ],
        output_config: { effort: "low" },
      },
      { protocol: "anthropic", session: "brand-new-sess", path: "/v1/messages", state: {} },
    );
    assert.equal(freshOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);

    // Warm main session on "sess-zcode" with <system-reminder> and tools
    const mainState = {};
    const mainBody = {
      model: "claude-opus-5-5",
      max_tokens: 64000,
      system: `Agent System\n${BIG_PAD}`,
      tools: [{ name: "Read", input_schema: { type: "object" } }],
      messages: [
        { role: "user", content: "<system-reminder>Env context</system-reminder>\nFix bug A" },
        { role: "assistant", content: "Investigating bug A." },
        { role: "user", content: "Check line 42" },
      ],
      output_config: { effort: "high" },
    };
    await hookOnRequest(mainBody, {
      protocol: "anthropic",
      session: "sess-zcode",
      path: "/v1/messages",
      state: mainState,
    });
    await hookOnResponse({ content: [{ type: "text", text: "Fixed." }] }, { success: true, state: mainState });

    // 2. ZCode-style memory extract: stripped <system-reminder> in messages[0], expanded tools, shared m1, effort disabled, max_tokens=4096
    const zcodeExtractOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 4096,
        system: `Agent System\n${BIG_PAD}`,
        tools: [
          { name: "Read", input_schema: { type: "object" } },
          { name: "WriteMemory", input_schema: { type: "object" } },
        ],
        messages: [
          { role: "user", content: "Fix bug A" }, // <system-reminder> stripped!
          { role: "assistant", content: "Investigating bug A." },
          { role: "user", content: "Extract durable memories" },
        ],
        thinking: { type: "disabled" },
      },
      {
        protocol: "anthropic",
        session: "sess-zcode",
        path: "/v1/messages",
        options: { relaySecret: TEST_SECRET, auxIncompatiblePolicy: "current_low" },
      },
    );
    assert.equal(zcodeExtractOut, undefined, "already disabled, no effort mutation needed");
    let diags = getAuxRoutingDiagnostics();
    assert.equal(diags.length, 1);
    assert.equal(diags[0].detector, "capped_downgrade");
    assert.equal(diags[0].compatible, false);
    assert.equal(diags[0].reason, "frame_mismatch");
    assert.equal(diags[0].sessionIsolated, true);

    // 3. Tool-stripped branch: same messages[1..2], tools removed, effort stays high (not downgraded), max_tokens=4096 -> current_low rewrites to low!
    const strippedToolsOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 4096,
        system: `Agent System\n${BIG_PAD}`,
        messages: [
          { role: "user", content: "Fix bug A" },
          { role: "assistant", content: "Investigating bug A." },
          { role: "user", content: "Verify completion without tools" },
        ],
        output_config: { effort: "high" },
      },
      {
        protocol: "anthropic",
        session: "sess-zcode",
        path: "/v1/messages",
        options: { relaySecret: TEST_SECRET, auxIncompatiblePolicy: "current_low" },
      },
    );
    assert.ok(strippedToolsOut);
    assert.equal(strippedToolsOut.output_config.effort, "low");
    diags = getAuxRoutingDiagnostics();
    assert.equal(diags.at(-1).detector, "tool_stripped_branch");

    // 4. User manually switches effort to low in UI (max_tokens stays 64000, tools intact) -> classified MAIN, NOT aux!
    const uiSwitchState = {};
    const uiSwitchOut = await hookOnRequest(
      {
        ...mainBody,
        messages: [
          ...mainBody.messages,
          { role: "assistant", content: "Checked line 42." },
          { role: "user", content: "Quick follow-up at low effort" },
        ],
        output_config: { effort: "low" },
      },
      {
        protocol: "anthropic",
        session: "sess-zcode",
        path: "/v1/messages",
        state: uiSwitchState,
      },
    );
    assert.equal(uiSwitchOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 2, "UI manual switch must not log as aux");
    await hookOnResponse({ content: [{ type: "text", text: "Sure." }] }, { success: true, state: uiSwitchState });
    assert.equal(getMainSessionState("sess-zcode").effort, "low", "UI manual switch updates main session effort");
  });
});

describe("Phase 2: B2 LCP Prefix Compatibility & Main State Isolation", () => {
  beforeEach(resetAllState);

  it("distinguishes lcp_matched, frame_mismatch, message_0_mismatch, and history_diverged, and isolates origins", () => {
    const baseSystem = "System rules";
    const baseTools = [{ type: "function", function: { name: "read", parameters: {} } }];
    const msgs = [
      { role: "user", content: "u0" },
      { role: "assistant", content: "a1" },
      { role: "user", content: "u2" },
      { role: "assistant", content: "a3" },
    ];
    const mainSnap = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      tools: baseTools,
      messages: [{ role: "system", content: baseSystem }, ...msgs],
    });
    const mainState = {
      ...mainSnap,
      turnFingerprintSet: new Set(mainSnap.rawTurnFingerprints),
    };

    // 1. Exact continuous prefix + new aux turn -> compatible: true
    const compatSnap = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      tools: baseTools,
      messages: [{ role: "system", content: baseSystem }, ...msgs, { role: "user", content: "aux" }],
    });
    assert.deepEqual(evaluatePrefixCompatibility(mainState, compatSnap), {
      compatible: true,
      lcpMessages: 4,
      reason: "lcp_matched",
    });

    // 2. Tools changed -> frame_mismatch
    const toolsChangedSnap = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      tools: [...baseTools, { type: "function", function: { name: "extra", parameters: {} } }],
      messages: [{ role: "system", content: baseSystem }, ...msgs, { role: "user", content: "aux" }],
    });
    assert.deepEqual(evaluatePrefixCompatibility(mainState, toolsChangedSnap), {
      compatible: false,
      lcpMessages: 0,
      reason: "frame_mismatch",
    });

    // 3. First message changed -> message_0_mismatch
    const m0ChangedSnap = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      tools: baseTools,
      messages: [
        { role: "system", content: baseSystem },
        { role: "user", content: "u0_stripped" },
        ...msgs.slice(1),
        { role: "user", content: "aux" },
      ],
    });
    assert.deepEqual(evaluatePrefixCompatibility(mainState, m0ChangedSnap), {
      compatible: false,
      lcpMessages: 0,
      reason: "message_0_mismatch",
    });

    // 4. Mid-conversation divergence (< 50% continuous prefix) -> history_diverged
    const divergedSnap = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      tools: baseTools,
      messages: [
        { role: "system", content: baseSystem },
        msgs[0],
        { role: "assistant", content: "a1_rewritten" },
        { role: "user", content: "u2_rewritten" },
        { role: "assistant", content: "a3_rewritten" },
        { role: "user", content: "aux" },
      ],
    });
    assert.deepEqual(evaluatePrefixCompatibility(mainState, divergedSnap), {
      compatible: false,
      lcpMessages: 1,
      reason: "history_diverged",
    });
  });

  it("isolates mainSessionMap by originScope so remote origin never sees local main state", async () => {
    const stateLocal = {};
    await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 64000,
        messages: [{ role: "user", content: "secret local work" }],
        output_config: { effort: "high" },
      },
      { protocol: "anthropic", origin: "local", session: "shared-id", path: "/v1/messages", state: stateLocal },
    );
    await hookOnResponse({ content: [{ type: "text", text: "ok" }] }, { success: true, state: stateLocal });

    assert.ok(getMainSessionState("shared-id", "local"));
    assert.equal(getMainSessionState("shared-id", "remote"), null);
  });
});

describe("Phase 2: B3 Dual-Path Routing, Hot-Reload, & 4-Protocol Session Isolation", () => {
  beforeEach(resetAllState);

  it("routes compatible cross-model aux back to main model via relay, and enforces keep / current_low / fallback_model + stable auxSessionId across all 4 protocols", async () => {
    await seedCatalog([
      {
        id: "claude-opus-5-5",
        name: "Claude Opus 5.5",
        provider: "MODEL_PROVIDER_ANTHROPIC",
        quota_group: "3p",
        thinking_levels: ["low", "medium", "high"],
        capabilities: { thinking: true, images: true },
      },
      {
        id: "gemini-3.8-flash",
        name: "Gemini 3.8 Flash",
        provider: "MODEL_PROVIDER_GOOGLE",
        quota_group: "gemini",
        thinking_levels: ["low", "medium", "high"],
        capabilities: { thinking: true, images: true },
      },
      {
        id: "claude-haiku-4-5",
        name: "Claude Haiku 4.5",
        provider: "MODEL_PROVIDER_ANTHROPIC",
        quota_group: "3p",
        thinking_levels: ["low", "high"],
        capabilities: { thinking: true, images: true },
      },
    ]);

    const tmpCfgDir = fs.mkdtempSync(path.join(os.tmpdir(), "agy2api-plugins-hot-"));
    try {
      const pluginsJsonPath = path.join(tmpCfgDir, "plugins.json");
      const writePluginsJson = (opts) => {
        fs.writeFileSync(
          pluginsJsonPath,
          JSON.stringify({
            plugins: [{ spec: "magpie-agy2api-plugin", off: false, options: opts }],
          }),
        );
      };
      writePluginsJson({
        preserveCacheEffort: true,
        auxIncompatiblePolicy: "current_low",
        auxFallbackModel: "gemini-3.8-flash",
        auxFallbackEffort: "low",
        relaySecret: TEST_SECRET,
      });

      setPluginRuntimeContext({ directory: tmpCfgDir });

      const sent = [];
      const agyFetch = createAgy2ApiFetch({
        baseUrl: "http://127.0.0.1:8017",
        apiKey: "sk-test",
        fetchImpl: async (url, init) => {
          sent.push({
            url: String(url),
            headers: new Headers(init.headers),
            body: JSON.parse(init.body),
          });
          return new Response(JSON.stringify({ id: "msg_1", type: "message" }), { status: 200 });
        },
      });

      // 1. Warm main session (Anthropic)
      const mainBody = {
        model: "claude-opus-5-5",
        max_tokens: 64000,
        system: `System\n${BIG_PAD}`,
        tools: [{ name: "Read", input_schema: { type: "object" } }],
        messages: [
          { role: "user", content: "<system-reminder>Env</system-reminder>\nTurn 1" },
          { role: "assistant", content: "Reply 1" },
          { role: "user", content: "Turn 2" },
        ],
        output_config: { effort: "high" },
        metadata: { user_id: '{"device_id":"d1","session_id":"orig-sess-1"}' },
      };
      const mainState = {};
      await hookOnRequest(mainBody, {
        protocol: "anthropic",
        session: "orig-sess-1",
        path: "/v1/messages",
        state: mainState,
      });
      await agyFetch("http://127.0.0.1:8017/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-session-id": "orig-sess-1" },
        body: JSON.stringify(mainBody),
      });
      await hookOnResponse({ content: [{ type: "text", text: "Reply 2" }] }, { success: true, state: mainState });

      // 2. Branch 2: Compatible aux request arriving on claude-haiku-4-5 -> relays back to agy2api/claude-opus-5-5 high, keeps orig-sess-1!
      const compatCrossBody = {
        model: "claude-haiku-4-5",
        max_tokens: 4096,
        system: mainBody.system,
        tools: mainBody.tools,
        messages: [...mainBody.messages, { role: "user", content: "Aux memory extract" }],
        output_config: { effort: "low" },
        metadata: { user_id: '{"device_id":"d1","session_id":"orig-sess-1"}' },
      };
      const hookCompatOut = await hookOnRequest(compatCrossBody, {
        protocol: "anthropic",
        session: "orig-sess-1",
        path: "/v1/messages",
      });
      assert.ok(hookCompatOut?.[RELAY_FIELD]);
      const mwCompatOut = mwOnRequest(hookCompatOut, {
        protocol: "anthropic",
        options: { relaySecret: TEST_SECRET },
      });
      assert.equal(mwCompatOut.model, "agy2api/claude-opus-5-5");
      assert.equal(mwCompatOut.output_config.effort, "high");
      assert.equal(RELAY_FIELD in mwCompatOut, false);
      await agyFetch("http://127.0.0.1:8017/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-session-id": "orig-sess-1" },
        body: JSON.stringify({ ...mwCompatOut, model: "claude-opus-5-5" }),
      });
      assert.equal(JSON.parse(sent[1].body.metadata.user_id).session_id, "orig-sess-1");

      // 3. Branch 3a: Incompatible (<system-reminder> stripped) with default "current_low" -> keeps model, rewrites effort to low, isolates session!
      const incompBody = {
        model: "claude-opus-5-5",
        max_tokens: 4096,
        system: mainBody.system,
        tools: mainBody.tools,
        messages: [
          { role: "user", content: "Turn 1" }, // stripped <system-reminder>
          { role: "assistant", content: "Reply 1" },
          { role: "user", content: "Extract memory" },
        ],
        output_config: { effort: "medium" },
        metadata: { user_id: "user_abc_account__session_11223344-5566-7788-99aa-bbccddeeff00" },
      };
      const hookLowOut = await hookOnRequest(incompBody, {
        protocol: "anthropic",
        session: "orig-sess-1",
        path: "/v1/messages",
      });
      assert.equal(hookLowOut.output_config.effort, "low");
      assert.equal(RELAY_FIELD in hookLowOut, false);

      await agyFetch("http://127.0.0.1:8017/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-session-id": "orig-sess-1",
          "x-claude-code-session-id": "orig-sess-1",
          "x-opencode-session": "orig-sess-1",
        },
        body: JSON.stringify(hookLowOut),
      });
      const auxSid1 = sent[2].headers.get("x-session-id");
      assert.match(auxSid1, /^agy2api-aux-v1-[0-9a-f]{32}$/);
      assert.equal(sent[2].headers.get("x-claude-code-session-id"), null);
      assert.equal(sent[2].headers.get("x-opencode-session"), null);
      assert.equal(
        sent[2].body.metadata.user_id,
        `user_abc_account__session_${auxSid1}`,
      );
      assert.equal(sent[2].body.output_config.effort, "low", "isolated ticket must NOT upgrade back to high!");

      // Second round of the SAME aux task reuses the EXACT SAME auxSessionId!
      const incompBodyRound2 = {
        ...incompBody,
        messages: [
          ...incompBody.messages,
          { role: "assistant", content: "Working..." },
          { role: "user", content: "Continue" },
        ],
      };
      const hookLowOut2 = await hookOnRequest(incompBodyRound2, {
        protocol: "anthropic",
        session: "orig-sess-1",
        path: "/v1/messages",
      });
      await agyFetch("http://127.0.0.1:8017/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-session-id": "orig-sess-1" },
        body: JSON.stringify(hookLowOut2),
      });
      assert.equal(sent[3].headers.get("x-session-id"), auxSid1);

      // 4. Hot-reload plugins.json to "fallback_model" (wait >1s or bump mtime + reset cache check via future nowFn)
      writePluginsJson({
        preserveCacheEffort: true,
        auxIncompatiblePolicy: "fallback_model",
        auxFallbackModel: "gemini-3.8-flash",
        auxFallbackEffort: "low",
        relaySecret: TEST_SECRET,
      });
      const futureNow = () => Date.now() + 2000;
      const hookFbOut = await hookOnRequest(incompBody, {
        protocol: "anthropic",
        session: "orig-sess-1",
        path: "/v1/messages",
        nowFn: futureNow,
      });
      assert.ok(hookFbOut[RELAY_FIELD]);
      const mwFbOut = mwOnRequest(hookFbOut, {
        protocol: "anthropic",
        options: { relaySecret: TEST_SECRET },
      });
      assert.equal(mwFbOut.model, "agy2api/gemini-3.8-flash");
      assert.equal(mwFbOut.output_config.effort, "low");

      await agyFetch("http://127.0.0.1:8017/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-session-id": "orig-sess-1" },
        body: JSON.stringify({ ...mwFbOut, model: "gemini-3.8-flash" }),
      });
      assert.equal(sent[4].headers.get("x-session-id"), auxSid1);

      // 5. Hot-reload to "keep" -> does not rewrite effort or model, still isolates session!
      writePluginsJson({
        preserveCacheEffort: true,
        auxIncompatiblePolicy: "keep",
        relaySecret: TEST_SECRET,
      });
      const futureNow2 = () => Date.now() + 4000;
      const hookKeepOut = await hookOnRequest(incompBody, {
        protocol: "anthropic",
        session: "orig-sess-1",
        path: "/v1/messages",
        nowFn: futureNow2,
      });
      assert.equal(hookKeepOut, undefined);
      await agyFetch("http://127.0.0.1:8017/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-session-id": "orig-sess-1" },
        body: JSON.stringify(incompBody),
      });
      assert.equal(sent[5].headers.get("x-session-id"), auxSid1);
      assert.equal(sent[5].body.output_config.effort, "medium");

      // 6. Test session isolation on chat, responses, and gemini protocols
      writePluginsJson({
        preserveCacheEffort: true,
        auxIncompatiblePolicy: "current_low",
        relaySecret: TEST_SECRET,
      });
      for (const [proto, urlPath, bodyObj] of [
        [
          "chat",
          "http://127.0.0.1:8017/v1/chat/completions",
          {
            model: "claude-opus-5-5",
            max_completion_tokens: 4096,
            reasoning_effort: "medium",
            metadata: { purpose: "project_memory_extract" },
            messages: [{ role: "user", content: "extract" }],
          },
        ],
        [
          "responses",
          "http://127.0.0.1:8017/v1/responses",
          {
            model: "claude-opus-5-5",
            max_output_tokens: 4096,
            reasoning: { effort: "medium" },
            metadata: { purpose: "project_memory_extract" },
            input: [{ type: "message", role: "user", content: "extract" }],
          },
        ],
        [
          "gemini",
          "http://127.0.0.1:8017/v1beta/models/gemini-3.8-flash:generateContent",
          {
            generationConfig: { maxOutputTokens: 4096, thinkingConfig: { thinkingLevel: "medium" } },
            metadata: { purpose: "project_memory_extract" },
            contents: [{ role: "user", parts: [{ text: "extract" }] }],
          },
        ],
      ]) {
        const hOut = await hookOnRequest(bodyObj, {
          protocol: proto,
          session: `sess-${proto}`,
          path: new URL(urlPath).pathname,
          nowFn: () => Date.now() + 6000,
          options: { auxIncompatiblePolicy: "current_low" },
        });
        assert.ok(hOut);
        await agyFetch(urlPath, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-session-id": `sess-${proto}`,
            session_id: `sess-${proto}`,
            conversation_id: `sess-${proto}`,
          },
          body: JSON.stringify(hOut),
        });
        const last = sent.at(-1);
        assert.match(last.headers.get("x-session-id"), /^agy2api-aux-v1-[0-9a-f]{32}$/);
        assert.equal(last.headers.get("session_id"), null);
        assert.equal(last.headers.get("conversation_id"), null);
      }
    } finally {
      fs.rmSync(tmpCfgDir, { recursive: true, force: true });
    }
  });
});

describe("Phase 2: B4 Cross-Model Validation & Diagnostics", () => {
  beforeEach(resetAllState);

  it("rejects unsafe fallback switches and falls back to current_low with exact diagnostic reasons", async () => {
    const models = [
      {
        id: "gemini-text-small",
        name: "Gemini Text Small",
        provider: "MODEL_PROVIDER_GOOGLE",
        quota_group: "gemini",
        input_token_limit: 8000,
        thinking_levels: ["low", "high"],
        capabilities: { thinking: true, images: false },
      },
      {
        id: "gemini-full",
        name: "Gemini Full",
        provider: "MODEL_PROVIDER_GOOGLE",
        quota_group: "gemini-pro",
        input_token_limit: 1_000_000,
        thinking_levels: ["low", "medium", "high", "xhigh"],
        supported_mime_types: ["image/png", "video/mp4", "application/pdf"],
        capabilities: { thinking: true, images: true, video: true, pdf: true },
      },
      {
        id: "imagen-gen",
        name: "Imagen",
        provider: "MODEL_PROVIDER_GOOGLE",
        quota_group: "gemini",
        capabilities: { image_generation: true },
      },
      {
        id: "claude-haiku-small",
        name: "Claude Haiku Small",
        provider: "MODEL_PROVIDER_ANTHROPIC",
        quota_group: "3p-exhausted",
        input_token_limit: 200_000,
        thinking_levels: [],
        capabilities: { thinking: false, images: true },
      },
      {
        id: "gpt-no-think",
        name: "GPT No Think",
        provider: "MODEL_PROVIDER_OPENAI",
        quota_group: "3p",
        input_token_limit: 200_000,
        capabilities: { thinking: false, images: true },
      },
    ];
    const accounts = [
      {
        id: "acc1@example.com",
        state: "ready",
        tier: "g1-pro-tier",
        quota_at: new Date().toISOString(),
        quota: [
          { bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.8 },
          { bucket_id: "gemini-pro-5h", window: "5h", remaining_fraction: 0.8 },
          { bucket_id: "3p-5h", window: "5h", remaining_fraction: 0.8 },
          { bucket_id: "3p-exhausted-5h", window: "5h", remaining_fraction: 0 },
        ],
      },
    ];
    await seedCatalog(models, accounts);

    const check = (params) => validateCrossModelSwitch(params);

    // 1. Undiscovered model
    assert.equal(
      check({ body: { model: "claude-opus-5-5", messages: [] }, protocol: "anthropic", targetModelId: "nonexistent" }).reason,
      "model_not_discovered",
    );

    // 2. Non-text output model (image gen)
    assert.equal(
      check({ body: { model: "claude-opus-5-5", messages: [] }, protocol: "anthropic", targetModelId: "imagen-gen" }).reason,
      "non_text_output_model",
    );

    // 3. Quota exhausted (used === 100 && !aside)
    assert.equal(
      check({ body: { model: "claude-opus-5-5", messages: [] }, protocol: "anthropic", targetModelId: "claude-haiku-small" }).reason,
      "quota_exhausted",
    );

    // 4. Context limit check: pure-input limit on Google models vs combined input+output window on Anthropic/OpenAI
    assert.equal(
      check({
        body: { model: "claude-opus-5-5", max_tokens: 4096, messages: [{ role: "user", content: "A".repeat(15000) }] },
        protocol: "anthropic",
        targetModelId: "gemini-text-small", // 8000 pure-input limit: ~5030 + 800 <= 8000 (output 4096 not deducted)
      }).ok,
      true,
    );
    assert.equal(
      check({
        body: { model: "claude-opus-5-5", max_tokens: 4096, messages: [{ role: "user", content: "A".repeat(22000) }] },
        protocol: "anthropic",
        targetModelId: "gemini-text-small", // ~7360 + 800 > 8000
      }).reason,
      "context_exceeded",
    );

    // 5. Missing modalities: image, video, pdf
    assert.equal(
      check({
        body: { model: "claude-opus-5-5", messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: "x" } }] }] },
        protocol: "anthropic",
        targetModelId: "gemini-text-small",
      }).reason,
      "modality_unsupported:image",
    );
    assert.equal(
      check({
        body: { contents: [{ role: "user", parts: [{ inlineData: { mimeType: "video/mp4", data: "x" } }] }] },
        protocol: "gemini",
        targetModelId: "gemini-text-small",
      }).reason,
      "modality_unsupported:video",
    );
    assert.equal(
      check({
        body: { messages: [{ role: "user", content: [{ type: "document", source: { type: "base64", media_type: "application/pdf", data: "x" } }] }] },
        protocol: "anthropic",
        targetModelId: "gemini-text-small",
      }).reason,
      "modality_unsupported:pdf",
    );

    // 6. Same-protocol sealed thinking blocks
    assert.equal(
      check({
        body: {
          model: "claude-opus-5-5",
          messages: [{ role: "assistant", content: [{ type: "redacted_thinking", data: "secret" }] }],
        },
        protocol: "anthropic",
        targetModelId: "claude-haiku-4-5", // wait: use undiscovered? Let's test gpt-no-think for responses & seed another anthropic with quota
      }).reason,
      "model_not_discovered",
    );

    clearModelCache();
    await seedCatalog(
      [
        ...models,
        {
          id: "claude-haiku-ok",
          name: "Claude Haiku OK",
          provider: "MODEL_PROVIDER_ANTHROPIC",
          quota_group: "3p",
          input_token_limit: 200_000,
          thinking_levels: ["low"],
          capabilities: { thinking: true, images: true },
        },
      ],
      accounts,
    );
    assert.equal(
      check({
        body: {
          model: "claude-opus-5-5",
          messages: [{ role: "assistant", content: [{ type: "redacted_thinking", data: "secret" }] }],
        },
        protocol: "anthropic",
        targetModelId: "claude-haiku-ok",
      }).reason,
      "sealed_thinking_incompatible",
    );
    assert.equal(
      check({
        body: {
          model: "gpt-5",
          input: [{ type: "reasoning", id: "r1", encrypted_content: "enc-blob" }],
        },
        protocol: "responses",
        targetModelId: "gpt-no-think",
      }).reason,
      "sealed_thinking_incompatible",
    );

    // 7. Thinking level adaptation: xhigh -> high when target lacks xhigh; non-thinking -> "none"
    const adapted = check({
      body: { model: "gemini-full", messages: [{ role: "user", content: "hi" }] },
      protocol: "chat",
      targetModelId: "gemini-text-small",
      targetEffort: "xhigh",
    });
    assert.equal(adapted.ok, true);
    assert.equal(adapted.adaptedEffort, "high");

    const nonThinking = check({
      body: { model: "gemini-full", reasoning_effort: "high", messages: [{ role: "user", content: "hi" }] },
      protocol: "chat",
      targetModelId: "gpt-no-think",
      targetEffort: "low",
    });
    assert.equal(nonThinking.ok, true);
    assert.equal(nonThinking.adaptedEffort, "none");

    // Verify middleware.onRequest strips thinking fields when toEffort === "none"
    const stripRelay = signRelayPayload(TEST_SECRET, {
      toModel: "agy2api/gpt-no-think",
      toEffort: "none",
      proto: "chat",
      ts: Date.now(),
      nonce: "nt1",
    });
    const strippedChat = mwOnRequest(
      { model: "gemini-full", reasoning_effort: "high", messages: [{ role: "user", content: "hi" }], [RELAY_FIELD]: stripRelay },
      { protocol: "chat", options: { relaySecret: TEST_SECRET } },
    );
    assert.equal(strippedChat.model, "agy2api/gpt-no-think");
    assert.equal("reasoning_effort" in strippedChat, false);

    // 8. End-to-end hook fallback to current_low when validation rejects + sanitized diagnostic record
    const fallbackRejectOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 4096,
        metadata: { purpose: "project_memory_extract" },
        messages: [{ role: "user", content: "SECRET PROMPT TEXT MUST NOT APPEAR IN DIAGS" }],
        output_config: { effort: "high" },
      },
      {
        protocol: "anthropic",
        session: "raw-secret-session-id-999",
        path: "/v1/messages",
        options: {
          relaySecret: TEST_SECRET,
          auxIncompatiblePolicy: "fallback_model",
          auxFallbackModel: "claude-haiku-small", // quota exhausted!
          auxFallbackEffort: "low",
        },
      },
    );
    assert.equal(fallbackRejectOut.output_config.effort, "low");
    assert.equal(RELAY_FIELD in fallbackRejectOut, false);
    const records = getAuxRoutingDiagnostics();
    assert.equal(records.length, 1);
    assert.equal(records[0].policy, "current_low");
    assert.equal(records[0].fallbackRejectedReason, "quota_exhausted");
    assert.equal(records[0].sessionIsolated, true);
    const serialized = JSON.stringify(records[0]);
    assert.equal(serialized.includes("SECRET PROMPT TEXT"), false);
    assert.equal(serialized.includes("raw-secret-session-id-999"), false);
    assert.equal(serialized.includes(TEST_SECRET), false);

    // 9. Missing audio modality, toolcall_unsupported, aside:true AI credits allowed, >6MiB payload fallback, preserveCacheEffort:false bypass, and 128-entry cap
    assert.equal(
      check({
        body: { contents: [{ role: "user", parts: [{ inlineData: { mimeType: "audio/mp3", data: "x" } }] }] },
        protocol: "gemini",
        targetModelId: "gemini-text-small",
      }).reason,
      "modality_unsupported:audio",
    );

    const { getDiscoveredModels } = await import("../lib/models.mjs");
    const catalog = getDiscoveredModels("http://127.0.0.1:8017");
    catalog["gpt-no-think"].capabilities.toolcall = false;
    assert.equal(
      check({
        body: { model: "claude-opus-5-5", tools: [{ name: "Read", input_schema: { type: "object" } }], messages: [{ role: "user", content: "hi" }] },
        protocol: "anthropic",
        targetModelId: "gpt-no-think",
      }).reason,
      "toolcall_unsupported",
    );

    // Quota exhausted WITH ai_credits (aside: true) is NOT rejected
    clearQuotaCache();
    await seedCatalog(models, [
      {
        id: "credits@example.com",
        state: "ready",
        tier: "g1-pro-tier",
        ai_credits: true,
        credit_balance: 500,
        quota_at: new Date().toISOString(),
        quota: [{ bucket_id: "3p-exhausted-5h", window: "5h", remaining_fraction: 0 }],
      },
    ]);
    assert.equal(
      check({
        body: { model: "claude-opus-5-5", messages: [{ role: "user", content: "hi" }] },
        protocol: "anthropic",
        targetModelId: "claude-haiku-small",
      }).ok,
      true,
    );

    const bigOver6MB = "B".repeat(6 * 1024 * 1024 + 512);
    const over6MbOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 4096,
        metadata: { purpose: "project_memory_extract" },
        messages: [{ role: "user", content: bigOver6MB }],
        output_config: { effort: "high" },
      },
      {
        protocol: "anthropic",
        session: "sess-6mb",
        path: "/v1/messages",
        options: {
          relaySecret: TEST_SECRET,
          auxIncompatiblePolicy: "fallback_model",
          auxFallbackModel: "gemini-full",
          auxFallbackEffort: "low",
        },
      },
    );
    assert.equal(RELAY_FIELD in over6MbOut, false);
    assert.equal(over6MbOut.output_config.effort, "low");
    assert.equal(getAuxRoutingDiagnostics().at(-1).fallbackRejectedReason, "payload_too_large");

    const disabledOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 4096,
        metadata: { purpose: "project_memory_extract" },
        messages: [{ role: "user", content: "hi" }],
        output_config: { effort: "high" },
      },
      {
        protocol: "anthropic",
        session: "sess-off",
        path: "/v1/messages",
        options: { preserveCacheEffort: false, auxIncompatiblePolicy: "current_low" },
      },
    );
    assert.equal(disabledOut, undefined);

    // Diagnostics ring buffer caps at 128
    clearAuxRoutingDiagnostics();
    for (let i = 0; i < 140; i++) {
      await hookOnRequest(
        {
          model: "claude-opus-5-5",
          max_tokens: 2048,
          metadata: { purpose: "project_memory_extract" },
          messages: [{ role: "user", content: `item ${i}` }],
          output_config: { effort: "low" },
        },
        {
          protocol: "anthropic",
          session: `ring-${i}`,
          path: "/v1/messages",
          options: { auxIncompatiblePolicy: "keep" },
        },
      );
    }
    assert.equal(getAuxRoutingDiagnostics().length, 128);

    // 10. Cross-protocol translation (Chat hook with auto/ prefix -> Gemini fetch) & foreign provider non-interference
    clearAuxRoutingDiagnostics();
    const foreignOut = await hookOnRequest(
      {
        model: "openai/gpt-6.2-sol",
        max_completion_tokens: 4096,
        reasoning_effort: "low",
        metadata: { purpose: "project_memory_extract" },
        messages: [{ role: "user", content: BIG_PAD }],
      },
      { protocol: "chat", session: "foreign-sess", path: "/v1/chat/completions" },
    );
    assert.equal(foreignOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);

    // Unprefixed model not in discovered agy2api catalog is also left untouched
    const nonAgyMainState = {};
    await hookOnRequest(
      {
        model: "gpt-6.2-sol",
        max_completion_tokens: 64000,
        reasoning_effort: "high",
        messages: [{ role: "user", content: BIG_PAD }],
      },
      { protocol: "chat", session: "non-agy-sess", path: "/v1/chat/completions", state: nonAgyMainState },
    );
    assert.equal(nonAgyMainState._agy2apiMainCandidate, undefined);

    // Chat hook (auto/gemini-full) + translated Gemini fetch in same default origin preserves chat frameDigest!
    const sentTrans = [];
    const transFetch = createAgy2ApiFetch({
      baseUrl: "http://127.0.0.1:8017",
      apiKey: "sk-pub",
      fetchImpl: async (url, init) => {
        sentTrans.push({ url: String(url), headers: new Headers(init.headers), body: JSON.parse(init.body) });
        return new Response(JSON.stringify({ candidates: [{ content: { role: "model", parts: [{ text: "R1" }] } }] }), { status: 200 });
      },
    });
    const chatState = {};
    const chatMain = {
      model: "auto/gemini-full",
      max_completion_tokens: 65536,
      reasoning_effort: "xhigh",
      tools: [{ type: "function", function: { name: "Read", parameters: { type: "object" } } }],
      messages: [
        { role: "system", content: `Sys\n${BIG_PAD}` },
        { role: "user", content: "<system-reminder>Deferred</system-reminder>\nQuestion 1" },
      ],
    };
    await hookOnRequest(chatMain, { protocol: "chat", session: "trans-sess", path: "/v1/chat/completions", state: chatState });
    await transFetch("http://127.0.0.1:8017/v1beta/models/gemini-full:generateContent", {
      method: "POST",
      headers: { "x-magpie-session": "trans-sess", "x-magpie-effort": "xhigh" },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: `Sys\n${BIG_PAD}` }] },
        tools: [{ functionDeclarations: [{ name: "Read", parameters: { type: "OBJECT" } }] }],
        contents: [{ role: "user", parts: [{ text: "<system-reminder>Deferred</system-reminder>\nQuestion 1" }] }],
        generationConfig: { maxOutputTokens: 65536, thinkingConfig: { thinkingLevel: "high" } },
      }),
    });
    await hookOnResponse({ choices: [{ message: { role: "assistant", content: "R1" } }] }, { success: true, state: chatState });

    // Next Chat auxiliary call WITH compatible prefix -> matches chat frameDigest (not overwritten by gemini fetch!)
    const chatCompatAux = {
      ...chatMain,
      max_completion_tokens: 4096,
      reasoning_effort: "low",
      messages: [
        ...chatMain.messages,
        { role: "assistant", content: "R1" },
        { role: "user", content: "Aux extract" },
      ],
    };
    const compatRes = await hookOnRequest(chatCompatAux, { protocol: "chat", session: "trans-sess", path: "/v1/chat/completions" });
    assert.equal(compatRes, undefined);
    assert.equal(getAuxRoutingDiagnostics().at(-1).compatible, true);

    // Next Chat auxiliary call WITH incompatible prefix -> switches to fallback gemini-text-small via relay & isolates session on translated Gemini fetch!
    const mediumPad = "M".repeat(33 * 1024);
    const chatIncompAux = {
      model: "auto/gemini-full",
      max_completion_tokens: 2048,
      reasoning_effort: "low",
      tools: [
        { type: "function", function: { name: "Read", parameters: { type: "object" } } },
        { type: "function", function: { name: "ExpandedMcp", parameters: { type: "object" } } },
      ],
      messages: [
        { role: "system", content: "Sys" },
        { role: "user", content: `Question 1\n${mediumPad}` }, // stripped <system-reminder>, >=32KiB for structural_heuristic
        { role: "assistant", content: "R1" },
        { role: "user", content: "Aux extract" },
      ],
    };
    const incompHookRes = await hookOnRequest(chatIncompAux, {
      protocol: "chat",
      session: "trans-sess",
      path: "/v1/chat/completions",
      options: {
        relaySecret: TEST_SECRET,
        auxIncompatiblePolicy: "fallback_model",
        auxFallbackModel: "gemini-full",
        auxFallbackEffort: "low",
      },
    });
    assert.ok(incompHookRes?.[RELAY_FIELD]);
    const incompMwRes = mwOnRequest(incompHookRes, { protocol: "chat", options: { relaySecret: TEST_SECRET } });
    assert.equal(incompMwRes.model, "agy2api/gemini-full");
    await transFetch("http://127.0.0.1:8017/v1beta/models/gemini-full:generateContent", {
      method: "POST",
      headers: { "x-magpie-session": "trans-sess" },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: "Question 1" }] }],
        generationConfig: { maxOutputTokens: 2048, thinkingConfig: { thinkingLevel: "low" } },
      }),
    });
    assert.match(sentTrans.at(-1).headers.get("x-session-id"), /^agy2api-aux-v1-[0-9a-f]{32}$/);
  });
});

describe("Phase 2: B5 FrameDigest Coverage Across Tool/Function Config Slots", () => {
  beforeEach(resetAllState);

  it("includes Gemini toolConfig/cachedContent, Anthropic tool_choice, OpenAI functions/function_call/tool_choice, and Responses tool_choice in frameDigest and fetch prefixKey", async () => {
    const turnsGem = [
      { role: "user", parts: [{ text: `Turn 1\n${BIG_PAD}` }] },
      { role: "model", parts: [{ text: "Reply 1" }] },
    ];
    const gemTools = [{ functionDeclarations: [{ name: "Read", parameters: { type: "OBJECT" } }] }];
    const gemBase = extractConversationSnapshot("gemini", {
      systemInstruction: { parts: [{ text: "Sys" }] },
      tools: gemTools,
      toolConfig: { functionCallingConfig: { mode: "AUTO" } },
      cachedContent: "cachedContents/buf-1",
      contents: turnsGem,
    });
    const gemToolCfgChanged = extractConversationSnapshot("gemini", {
      systemInstruction: { parts: [{ text: "Sys" }] },
      tools: gemTools,
      toolConfig: { functionCallingConfig: { mode: "ANY", allowedFunctionNames: ["Read"] } },
      cachedContent: "cachedContents/buf-1",
      contents: [...turnsGem, { role: "user", parts: [{ text: "aux" }] }],
    });
    const gemSnakeToolCfg = extractConversationSnapshot("gemini", {
      system_instruction: { parts: [{ text: "Sys" }] },
      tools: gemTools,
      tool_config: { functionCallingConfig: { mode: "NONE" } },
      cached_content: "cachedContents/buf-1",
      contents: [...turnsGem, { role: "user", parts: [{ text: "aux" }] }],
    });
    const gemCacheRefChanged = extractConversationSnapshot("gemini", {
      systemInstruction: { parts: [{ text: "Sys" }] },
      tools: gemTools,
      toolConfig: { functionCallingConfig: { mode: "AUTO" } },
      cachedContent: "cachedContents/buf-2",
      contents: [...turnsGem, { role: "user", parts: [{ text: "aux" }] }],
    });
    assert.notEqual(gemBase.frameDigest, gemToolCfgChanged.frameDigest);
    assert.notEqual(gemBase.frameDigest, gemSnakeToolCfg.frameDigest);
    assert.notEqual(gemBase.frameDigest, gemCacheRefChanged.frameDigest);
    assert.equal(evaluatePrefixCompatibility(gemBase, gemToolCfgChanged).reason, "frame_mismatch");
    assert.equal(evaluatePrefixCompatibility(gemBase, gemSnakeToolCfg).reason, "frame_mismatch");
    assert.equal(evaluatePrefixCompatibility(gemBase, gemCacheRefChanged).reason, "frame_mismatch");

    // Anthropic tool_choice
    const anthTools = [{ name: "Read", input_schema: { type: "object" } }];
    const anthMsgs = [
      { role: "user", content: `Turn 1\n${BIG_PAD}` },
      { role: "assistant", content: "Reply 1" },
    ];
    const anthAuto = extractConversationSnapshot("anthropic", {
      model: "claude-opus-5-5",
      system: "Sys",
      tools: anthTools,
      tool_choice: { type: "auto" },
      messages: anthMsgs,
    });
    const anthForced = extractConversationSnapshot("anthropic", {
      model: "claude-opus-5-5",
      system: "Sys",
      tools: anthTools,
      tool_choice: { type: "tool", name: "Read" },
      messages: [...anthMsgs, { role: "user", content: "aux" }],
    });
    assert.notEqual(anthAuto.frameDigest, anthForced.frameDigest);
    assert.equal(evaluatePrefixCompatibility(anthAuto, anthForced).reason, "frame_mismatch");

    // OpenAI Chat legacy functions, function_call, and tool_choice
    const chatMsgs = [
      { role: "system", content: "Sys" },
      { role: "user", content: `Turn 1\n${BIG_PAD}` },
      { role: "assistant", content: "Reply 1" },
    ];
    const chatFnAuto = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      functions: [{ name: "legacy_fn", parameters: { type: "object" } }],
      function_call: "auto",
      messages: chatMsgs,
    });
    assert.equal(chatFnAuto.hasTools, true, "legacy functions must set hasTools=true");
    const chatFnChanged = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      functions: [{ name: "legacy_fn_v2", parameters: { type: "object" } }],
      function_call: "auto",
      messages: [...chatMsgs, { role: "user", content: "aux" }],
    });
    const chatFnCallChanged = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      functions: [{ name: "legacy_fn", parameters: { type: "object" } }],
      function_call: { name: "legacy_fn" },
      messages: [...chatMsgs, { role: "user", content: "aux" }],
    });
    const chatToolChoiceChanged = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      tools: [{ type: "function", function: { name: "t1", parameters: {} } }],
      tool_choice: "required",
      messages: [...chatMsgs, { role: "user", content: "aux" }],
    });
    const chatToolChoiceAuto = extractConversationSnapshot("chat", {
      model: "gpt-oss-120b",
      tools: [{ type: "function", function: { name: "t1", parameters: {} } }],
      tool_choice: "auto",
      messages: chatMsgs,
    });
    assert.equal(evaluatePrefixCompatibility(chatFnAuto, chatFnChanged).reason, "frame_mismatch");
    assert.equal(evaluatePrefixCompatibility(chatFnAuto, chatFnCallChanged).reason, "frame_mismatch");
    assert.equal(evaluatePrefixCompatibility(chatToolChoiceAuto, chatToolChoiceChanged).reason, "frame_mismatch");

    // OpenAI Responses tool_choice
    const respAuto = extractConversationSnapshot("responses", {
      model: "gpt-oss-120b",
      instructions: "Sys",
      tools: [{ type: "function", name: "t1", parameters: {} }],
      tool_choice: "auto",
      input: [{ type: "message", role: "user", content: "u1" }],
    });
    const respNone = extractConversationSnapshot("responses", {
      model: "gpt-oss-120b",
      instructions: "Sys",
      tools: [{ type: "function", name: "t1", parameters: {} }],
      tool_choice: "none",
      input: [{ type: "message", role: "user", content: "u1" }, { type: "message", role: "user", content: "u2" }],
    });
    assert.equal(evaluatePrefixCompatibility(respAuto, respNone).reason, "frame_mismatch");

    // Verify fetch.mjs computePrefixKey also isolates Anthropic tool_choice and OpenAI function_call
    const sent = [];
    const agyFetch = createAgy2ApiFetch({
      baseUrl: "http://127.0.0.1:8017",
      apiKey: "sk-test",
      fetchImpl: async (_url, init) => {
        sent.push(JSON.parse(init.body));
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
    });
    await agyFetch("http://127.0.0.1:8017/v1/messages", {
      method: "POST",
      headers: { "x-session-id": "pf-tc" },
      body: JSON.stringify({
        model: "claude-opus-5-5",
        max_tokens: 64000,
        tools: anthTools,
        tool_choice: { type: "auto" },
        output_config: { effort: "high" },
        messages: anthMsgs,
      }),
    });
    await agyFetch("http://127.0.0.1:8017/v1/messages", {
      method: "POST",
      headers: { "x-session-id": "pf-tc" },
      body: JSON.stringify({
        model: "claude-opus-5-5",
        max_tokens: 4096,
        tools: anthTools,
        tool_choice: { type: "tool", name: "Read" },
        output_config: { effort: "low" },
        messages: [...anthMsgs, { role: "user", content: "next" }],
      }),
    });
    assert.equal(sent[1].output_config.effort, "low", "changed tool_choice must not upgrade effort in fetch.mjs");
  });
});

describe("Phase 2: B6 Negative Classification Guards (No False-Positive Aux Routing)", () => {
  beforeEach(resetAllState);

  it("never misclassifies manual low effort, shortened max_tokens, tool edits, manual model switch, normal subagents, or standalone requests without main session", async () => {
    await seedCatalog([
      {
        id: "claude-opus-5-5",
        name: "Claude Opus 5.5",
        provider: "MODEL_PROVIDER_ANTHROPIC",
        quota_group: "3p",
        thinking_levels: ["low", "medium", "high"],
        capabilities: { thinking: true, images: true },
      },
      {
        id: "claude-sonnet-5-5",
        name: "Claude Sonnet 5.5",
        provider: "MODEL_PROVIDER_ANTHROPIC",
        quota_group: "3p",
        thinking_levels: ["low", "medium", "high"],
        capabilities: { thinking: true, images: true },
      },
      {
        id: "gemini-3.8-flash",
        name: "Gemini 3.8 Flash",
        provider: "MODEL_PROVIDER_GOOGLE",
        quota_group: "gemini",
        thinking_levels: ["low", "medium", "high"],
        capabilities: { thinking: true, images: true },
      },
    ]);

    const commonOpts = {
      relaySecret: TEST_SECRET,
      auxIncompatiblePolicy: "fallback_model",
      auxFallbackModel: "gemini-3.8-flash",
      auxFallbackEffort: "low",
    };

    // 6. Standalone request with no active main session (even >32KB, low effort, capped max_tokens, no tools, multi-turn history)
    const standaloneState = {};
    const standaloneOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 1024,
        system: `Standalone\n${BIG_PAD}`,
        messages: [
          { role: "user", content: "Prior 1" },
          { role: "assistant", content: "Prior A1" },
          { role: "user", content: "Summarize" },
        ],
        output_config: { effort: "low" },
      },
      {
        protocol: "anthropic",
        session: "standalone-sess-0",
        path: "/v1/messages",
        state: standaloneState,
        options: commonOpts,
      },
    );
    assert.equal(standaloneOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);
    assert.ok(standaloneState._agy2apiMainCandidate, "standalone request is treated as main");

    // Seed active main session on "neg-sess-1" (high effort, 64000 max_tokens, 2 tools)
    const baseTools = [
      { name: "Read", input_schema: { type: "object" } },
      { name: "Bash", input_schema: { type: "object" } },
    ];
    const baseMsgs = [
      { role: "user", content: `<system-reminder>Env</system-reminder>\nTask 1\n${BIG_PAD}` },
      { role: "assistant", content: "Working on Task 1." },
      { role: "user", content: "Continue Task 1" },
    ];
    const m1State = {};
    await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 64000,
        system: "Main system",
        tools: baseTools,
        messages: baseMsgs,
        output_config: { effort: "high" },
      },
      { protocol: "anthropic", session: "neg-sess-1", path: "/v1/messages", state: m1State, options: commonOpts },
    );
    await hookOnResponse({ content: [{ type: "text", text: "Done Task 1." }] }, { success: true, state: m1State });

    // 2. Shortening max_tokens ONLY (64000 -> 2048) while keeping effort="high" and tools -> must stay MAIN
    const shortMaxState = {};
    const shortMaxOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 2048,
        system: "Main system",
        tools: baseTools,
        messages: [...baseMsgs, { role: "assistant", content: "Done Task 1." }, { role: "user", content: "Short answer please" }],
        output_config: { effort: "high" },
      },
      { protocol: "anthropic", session: "neg-sess-1", path: "/v1/messages", state: shortMaxState, options: commonOpts },
    );
    assert.equal(shortMaxOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);
    assert.ok(shortMaxState._agy2apiMainCandidate);

    // 3a. Modifying tool definitions (adding/removing MCP tool, hasTools stays true, even with shortened max_tokens=2048 at effort="high") -> must stay MAIN
    const modToolsState = {};
    const modToolsOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 2048,
        system: "Main system",
        tools: [{ name: "Read", input_schema: { type: "object", properties: { p: { type: "string" } } } }],
        messages: [...baseMsgs, { role: "assistant", content: "Done Task 1." }, { role: "user", content: "Use Read only" }],
        output_config: { effort: "high" },
      },
      { protocol: "anthropic", session: "neg-sess-1", path: "/v1/messages", state: modToolsState, options: commonOpts },
    );
    assert.equal(modToolsOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);
    assert.ok(modToolsState._agy2apiMainCandidate);

    // 3b. Clearing all tools (tools: []) in a normal turn with normal max_tokens=64000 (even if user also picked low effort) -> must stay MAIN
    const clearToolsState = {};
    const clearToolsOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 64000,
        system: "Main system",
        tools: [],
        messages: [...baseMsgs, { role: "assistant", content: "Done Task 1." }, { role: "user", content: "Chat mode without tools" }],
        output_config: { effort: "low" },
      },
      { protocol: "anthropic", session: "neg-sess-1", path: "/v1/messages", state: clearToolsState, options: commonOpts },
    );
    assert.equal(clearToolsOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);
    assert.ok(clearToolsState._agy2apiMainCandidate);

    // 1. User manually selects low effort in UI (normal max_tokens=64000, tools intact) -> must stay MAIN and update mainState.effort to "low"
    const userLowState = {};
    const userLowOut = await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 64000,
        system: "Main system",
        tools: baseTools,
        messages: [...baseMsgs, { role: "assistant", content: "Done Task 1." }, { role: "user", content: "Manual low effort turn" }],
        output_config: { effort: "low" },
      },
      { protocol: "anthropic", session: "neg-sess-1", path: "/v1/messages", state: userLowState, options: commonOpts },
    );
    assert.equal(userLowOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);
    await hookOnResponse({ content: [{ type: "text", text: "Low reply." }] }, { success: true, state: userLowState });
    assert.equal(getMainSessionState("neg-sess-1", undefined, Date.now(), undefined, "anthropic").effort, "low");

    // Restore high effort on neg-sess-1 to test manual model switch from high -> low/medium on another model
    const reHighState = {};
    await hookOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 64000,
        system: "Main system",
        tools: baseTools,
        messages: [...baseMsgs, { role: "assistant", content: "Done Task 1." }, { role: "user", content: "Back to high" }],
        output_config: { effort: "high" },
      },
      { protocol: "anthropic", session: "neg-sess-1", path: "/v1/messages", state: reHighState, options: commonOpts },
    );
    await hookOnResponse({ content: [{ type: "text", text: "High reply." }] }, { success: true, state: reHighState });

    // 4. User manually switches model mid-session (claude-opus-5-5 high 64000 -> claude-sonnet-5-5 low 32000, and external kiro/claude-sonnet-5-5) -> must NOT relay back to opus!
    const switchModelState = {};
    const switchModelOut = await hookOnRequest(
      {
        model: "claude-sonnet-5-5",
        max_tokens: 32000,
        system: "Main system",
        tools: baseTools,
        messages: [...baseMsgs, { role: "assistant", content: "Done Task 1." }, { role: "user", content: "Switched to Sonnet low" }],
        output_config: { effort: "low" },
      },
      { protocol: "anthropic", session: "neg-sess-1", path: "/v1/messages", state: switchModelState, options: commonOpts },
    );
    assert.equal(switchModelOut, undefined, "manual model switch must never be rewritten back to previous model");
    assert.equal(getAuxRoutingDiagnostics().length, 0);
    await hookOnResponse({ content: [{ type: "text", text: "Sonnet reply." }] }, { success: true, state: switchModelState });
    assert.equal(getMainSessionState("neg-sess-1", undefined, Date.now(), undefined, "anthropic").bareModel, "claude-sonnet-5-5");

    const switchForeignOut = await hookOnRequest(
      {
        model: "kiro/claude-sonnet-5-5",
        max_tokens: 4096,
        system: "Main system",
        tools: baseTools,
        messages: [...baseMsgs, { role: "assistant", content: "Done Task 1." }, { role: "user", content: "Foreign provider switch" }],
        output_config: { effort: "low" },
      },
      { protocol: "anthropic", session: "neg-sess-1", path: "/v1/messages", options: commonOpts },
    );
    assert.equal(switchForeignOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);

    // 5. Normal subagent: both kind="subagent" on parent session AND ZCode-style independent agent_<id> session with low effort + max_tokens=4096
    const subParentState = {};
    const subParentOut = await hookOnRequest(
      {
        model: "claude-sonnet-5-5",
        max_tokens: 4096,
        system: "Subagent prompt",
        messages: [...baseMsgs, { role: "user", content: "Subagent work" }],
        output_config: { effort: "low" },
      },
      {
        protocol: "anthropic",
        session: "neg-sess-1",
        kind: "subagent",
        path: "/v1/messages",
        state: subParentState,
        options: commonOpts,
      },
    );
    assert.equal(subParentOut, undefined);
    assert.equal(subParentState._agy2apiMainCandidate, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);

    const subZcodeState = {};
    const subZcodeOut = await hookOnRequest(
      {
        model: "gemini-3.8-flash",
        max_tokens: 4096,
        system: `Subagent prompt\n${BIG_PAD}`,
        messages: [
          { role: "user", content: "Subagent step 1" },
          { role: "assistant", content: "Step 1 done" },
          { role: "user", content: "Subagent step 2" },
        ],
        output_config: { effort: "low" },
      },
      {
        protocol: "anthropic",
        session: "agent_648a787e-17ad-4195-9383-3ab8d9cb4e72",
        path: "/v1/messages",
        state: subZcodeState,
        options: commonOpts,
      },
    );
    assert.equal(subZcodeOut, undefined);
    assert.equal(getAuxRoutingDiagnostics().length, 0);
  });
});

describe("Phase 2: B7 Fallback Model 429 Cooldown Isolation, Gateway Key Guard & 962K Boundary", () => {
  beforeEach(resetAllState);

  it("isolates model-level 429 on fallback_model B without cooling model A or provider, enforces post-middleware Gateway Key allowlist, and verifies 962K–973K context check", async () => {
    await seedCatalog([
      {
        id: "gemini-4-neon",
        name: "Gemini 4 Neon",
        provider: "MODEL_PROVIDER_GOOGLE",
        quota_group: "gemini",
        input_token_limit: 1_048_576,
        output_token_limit: 262_144,
        thinking_levels: ["low", "high", "xhigh"],
        capabilities: { thinking: true, images: true },
      },
      {
        id: "gemini-3.8-flash",
        name: "Gemini 3.8 Flash",
        provider: "MODEL_PROVIDER_GOOGLE",
        quota_group: "gemini",
        input_token_limit: 1_048_576,
        output_token_limit: 65_536,
        thinking_levels: ["low", "medium", "high"],
        capabilities: { thinking: true, images: true },
      },
    ]);

    const upstreamCalls = [];
    const modelCooldowns = new Map(); // provider/model -> retryAfterSec
    let providerDisabled = false;

    const agyFetch = createAgy2ApiFetch({
      baseUrl: "http://127.0.0.1:8017",
      apiKey: "sk-valid",
      fetchImpl: async (url, init) => {
        const u = String(url);
        const headers = new Headers(init.headers);
        upstreamCalls.push({ url: u, sessionId: headers.get("x-session-id") });
        if (u.includes("/models/gemini-3.8-flash:")) {
          return new Response(
            JSON.stringify({
              error: {
                code: 429,
                message: "All accounts for model gemini-3.8-flash-low are cooling down",
                status: "RESOURCE_EXHAUSTED",
              },
            }),
            {
              status: 429,
              headers: { "content-type": "application/json", "retry-after": "45" },
            },
          );
        }
        return new Response(
          JSON.stringify({
            candidates: [{ content: { role: "model", parts: [{ text: "Neon OK" }] } }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    });

    // Helper mirroring Magpie serveAgent (middleware.go:45-83 -> key_models.go -> route/cooldown)
    async function runSimulatedMagpieServeAgent({ rawBody, session, allowedModels = null }) {
      const hookState = {};
      const afterHook =
        (await hookOnRequest(rawBody, {
          protocol: "chat",
          session,
          path: "/v1/chat/completions",
          state: hookState,
          options: {
            relaySecret: TEST_SECRET,
            auxIncompatiblePolicy: "fallback_model",
            auxFallbackModel: "gemini-3.8-flash",
            auxFallbackEffort: "low",
          },
        })) ?? rawBody;

      const afterMw =
        mwOnRequest(afterHook, {
          protocol: "chat",
          options: { relaySecret: TEST_SECRET },
        }) ?? afterHook;

      const targetRef = afterMw.model.includes("/") ? afterMw.model : `agy2api/${afterMw.model}`;
      // Magpie s.serve checks keyHolds(r) AFTER middleware.onRequest (agentTurn, no magpieChoseKey)
      if (Array.isArray(allowedModels) && !allowedModels.includes(targetRef)) {
        return { status: 403, error: `key is not allowed to use ${targetRef}`, targetRef };
      }
      if (providerDisabled || modelCooldowns.has(targetRef)) {
        return { status: 429, cooled: true, targetRef };
      }

      const bare = targetRef.replace(/^agy2api\//, "");
      const res = await agyFetch(`http://127.0.0.1:8017/v1beta/models/${bare}:generateContent`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-magpie-session": session },
        body: JSON.stringify({
          contents: afterMw.messages
            .filter((m) => m.role !== "system")
            .map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] })),
          generationConfig: {
            maxOutputTokens: afterMw.max_completion_tokens,
            thinkingConfig: { thinkingLevel: afterMw.reasoning_effort || "high" },
          },
        }),
      });
      if (res.status === 429) {
        if (res.headers.get("x-magpie-sign-in") === "expired") {
          providerDisabled = true;
        } else {
          const errJson = await res.clone().json();
          if (errJson?.error?.model) {
            modelCooldowns.set(`agy2api/${errJson.error.model}`, Number(res.headers.get("retry-after") || 0));
          } else {
            providerDisabled = true;
          }
        }
        await hookOnResponse(null, { success: false, state: hookState });
        return { status: 429, res, targetRef };
      }
      const data = await res.json();
      await hookOnResponse({ choices: [{ message: { role: "assistant", content: "Neon OK" } }] }, { success: true, state: hookState });
      return { status: 200, data, targetRef };
    }

    // 1. Warm Model A (agy2api/gemini-4-neon) on main session
    const mainMsgs = [
      { role: "system", content: `Sys\n${BIG_PAD}` },
      { role: "user", content: "<system-reminder>R</system-reminder>\nMain 1" },
    ];
    const m1 = await runSimulatedMagpieServeAgent({
      rawBody: {
        model: "agy2api/gemini-4-neon",
        max_completion_tokens: 65536,
        reasoning_effort: "xhigh",
        messages: mainMsgs,
      },
      session: "sess-429-iso",
    });
    assert.equal(m1.status, 200);
    assert.equal(m1.targetRef, "agy2api/gemini-4-neon");

    // 2. Gateway Key restricted to ONLY ["agy2api/gemini-4-neon"] -> aux rewrite to gemini-3.8-flash is refused 403, NEVER bypassing key permissions!
    await runSimulatedMagpieServeAgent({
      rawBody: {
        model: "agy2api/gemini-4-neon",
        max_completion_tokens: 65536,
        reasoning_effort: "xhigh",
        messages: mainMsgs,
      },
      session: "sess-403-key",
      allowedModels: ["agy2api/gemini-4-neon"],
    });
    const callsBefore403 = upstreamCalls.length;
    const denied = await runSimulatedMagpieServeAgent({
      rawBody: {
        model: "agy2api/gemini-4-neon",
        max_completion_tokens: 4096,
        reasoning_effort: "low",
        messages: [
          { role: "system", content: `Sys\n${BIG_PAD}` },
          { role: "user", content: "Main 1" }, // stripped <system-reminder> -> incompatible aux
          { role: "assistant", content: "Neon OK" },
          { role: "user", content: "Extract memory" },
        ],
      },
      session: "sess-403-key",
      allowedModels: ["agy2api/gemini-4-neon"],
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.targetRef, "agy2api/gemini-3.8-flash");
    assert.equal(upstreamCalls.length, callsBefore403, "403 key check must block before upstream fetch");
    assert.equal(getAuxRoutingDiagnostics().at(-1).upstreamExecuted, undefined);

    // 3. Unrestricted (or both-allowed) key hits fallback_model B (gemini-3.8-flash) which returns model-level 429
    const b429 = await runSimulatedMagpieServeAgent({
      rawBody: {
        model: "agy2api/gemini-4-neon",
        max_completion_tokens: 4096,
        reasoning_effort: "low",
        messages: [
          { role: "system", content: `Sys\n${BIG_PAD}` },
          { role: "user", content: "Main 1" },
          { role: "assistant", content: "Neon OK" },
          { role: "user", content: "Extract memory" },
        ],
      },
      session: "sess-429-iso",
      allowedModels: ["agy2api/gemini-4-neon", "agy2api/gemini-3.8-flash"],
    });
    assert.equal(b429.status, 429);
    assert.equal(b429.targetRef, "agy2api/gemini-3.8-flash");
    assert.equal(b429.res.headers.get("retry-after"), "45");
    assert.equal(b429.res.headers.get("x-magpie-sign-in"), null);
    const b429Body = await b429.res.json();
    assert.equal(b429Body.error.model, "gemini-3.8-flash");
    assert.match(b429Body.error.message, /^model gemini-3\.8-flash:/);
    assert.match(upstreamCalls.at(-1).sessionId, /^agy2api-aux-v1-[0-9a-f]{32}$/);
    assert.equal(getAuxRoutingDiagnostics().at(-1).upstreamExecuted, true);
    assert.equal(getAuxRoutingDiagnostics().at(-1).upstreamOutcome, "isolated");

    // Only fallback_model B is cooled; provider is NOT disabled and Model A continues serving 200 OK!
    assert.equal(providerDisabled, false);
    assert.equal(modelCooldowns.get("agy2api/gemini-3.8-flash"), 45);
    assert.equal(modelCooldowns.has("agy2api/gemini-4-neon"), false);

    const m2 = await runSimulatedMagpieServeAgent({
      rawBody: {
        model: "agy2api/gemini-4-neon",
        max_completion_tokens: 65536,
        reasoning_effort: "xhigh",
        messages: [...mainMsgs, { role: "assistant", content: "Neon OK" }, { role: "user", content: "Main 2 continues" }],
      },
      session: "sess-429-iso",
      allowedModels: ["agy2api/gemini-4-neon", "agy2api/gemini-3.8-flash"],
    });
    assert.equal(m2.status, 200);
    assert.equal(upstreamCalls.at(-1).sessionId, "sess-429-iso");

    // 4. Verify all 6 real 962K–973K ZCode memory extraction requests (maxOutputTokens=5000) pass on 1M Gemini
    // (pure input limit 1,048,576) while 1.12M overflow requests and combined-window overflows are rejected
    for (const realBytes of [2_884_824, 2_898_167, 2_901_592, 2_912_025, 2_913_637, 2_917_665]) {
      const okGem = validateCrossModelSwitch({
        body: { model: "gemini-4-carbon", max_completion_tokens: 5000, messages: [{ role: "user", content: "stub" }] },
        bodyBytes: realBytes,
        protocol: "chat",
        targetModelId: "gemini-3.8-flash",
        targetEffort: "low",
      });
      assert.equal(okGem.ok, true, `expected ${realBytes}B to pass on 1,048,576 pure-input Gemini`);
    }

    // Even when max_completion_tokens is 65,536 (990K main/compat turn), Google pure-input limit does NOT deduct 65,536
    const pureInput990k = validateCrossModelSwitch({
      body: { model: "gemini-4-carbon", max_completion_tokens: 65_536, messages: [{ role: "user", content: "stub" }] },
      bodyBytes: 990_000 * 3,
      protocol: "chat",
      targetModelId: "gemini-3.8-flash",
      targetEffort: "low",
    });
    assert.equal(pureInput990k.ok, true);

    // 1.12M overflow (3,624,040B) is rejected
    const overflow112m = validateCrossModelSwitch({
      body: { model: "gemini-4-carbon", max_completion_tokens: 5000, messages: [{ role: "user", content: "stub" }] },
      bodyBytes: 3_624_040,
      protocol: "chat",
      targetModelId: "gemini-3.8-flash",
      targetEffort: "low",
    });
    assert.equal(overflow112m.ok, false);
    assert.equal(overflow112m.reason, "context_exceeded");

    // Combined input+output window on Anthropic (1,000,000) deducts exact outbound output reservation
    clearModelCache();
    await seedCatalog([
      {
        id: "claude-sonnet-5-5",
        name: "Claude Sonnet 5.5",
        provider: "MODEL_PROVIDER_ANTHROPIC",
        quota_group: "3p",
        input_token_limit: 1_000_000,
        output_token_limit: 128_000,
        thinking_levels: ["low", "medium", "high"],
        capabilities: { thinking: true, images: true },
      },
      {
        id: "gpt-oss-120b",
        name: "GPT OSS 120B",
        provider: "MODEL_PROVIDER_OPENAI",
        quota_group: "3p",
        input_token_limit: 131_072,
        output_token_limit: 32_768,
        thinking_levels: ["low", "medium", "high"],
        capabilities: { thinking: true },
      },
    ]);
    assert.equal(
      validateCrossModelSwitch({
        body: { model: "gemini-4-carbon", max_completion_tokens: 5000, messages: [{ role: "user", content: "stub" }] },
        bodyBytes: 2_884_824, // 961,608 + 16,384 + 5,000 = 982,992 <= 1,000,000
        protocol: "chat",
        targetModelId: "claude-sonnet-5-5",
        targetEffort: "low",
      }).ok,
      true,
    );
    assert.equal(
      validateCrossModelSwitch({
        body: { model: "gemini-4-carbon", max_completion_tokens: 32_000, messages: [{ role: "user", content: "stub" }] },
        bodyBytes: 2_884_824, // 961,608 + 16,384 + 32,000 = 1,009,992 > 1,000,000
        protocol: "chat",
        targetModelId: "claude-sonnet-5-5",
        targetEffort: "low",
      }).reason,
      "context_exceeded",
    );
    // Outbound max_tokens exceeding non-Google target output_token_limit (100,000 > 32,768) is rejected
    assert.equal(
      validateCrossModelSwitch({
        body: { model: "gemini-4-carbon", max_completion_tokens: 100_000, messages: [{ role: "user", content: "hi" }] },
        bodyBytes: 300,
        protocol: "chat",
        targetModelId: "gpt-oss-120b",
        targetEffort: "low",
      }).reason,
      "context_exceeded",
    );
    // Omitted max_tokens cross-protocol to Anthropic reserves target limit.output (128,000)
    assert.equal(
      validateCrossModelSwitch({
        body: { model: "gemini-4-carbon", messages: [{ role: "user", content: "stub" }] },
        bodyBytes: 900_000 * 3, // 900,000 + 16,384 + 128,000 = 1,044,384 > 1,000,000
        protocol: "chat",
        targetModelId: "claude-sonnet-5-5",
        targetEffort: "low",
      }).reason,
      "context_exceeded",
    );
      // Outbound max_tokens exceeding non-Google target output_token_limit is rejected even when limit.context === 0
      clearModelCache();
      await seedCatalog([
        {
          id: "claude-output-only",
          name: "Claude Output Only",
          provider: "MODEL_PROVIDER_ANTHROPIC",
          quota_group: "3p",
          output_token_limit: 16_384,
          thinking_levels: ["low", "high"],
          capabilities: { thinking: true },
        },
      ]);
      assert.equal(
        validateCrossModelSwitch({
          body: { model: "gemini-4-carbon", max_completion_tokens: 32_000, messages: [{ role: "user", content: "hi" }] },
          bodyBytes: 200,
          protocol: "chat",
          targetModelId: "claude-output-only",
          targetEffort: "low",
        }).reason,
        "context_exceeded",
      );
  });
});

describe("Phase 2: B8 Cold-Start plugin-auth.json Fallback & Multi-Login Scope Safety", () => {
  beforeEach(resetAllState);

  it("resolves unique agy2api / agy2api#<suffix> (and .bak fallback) before loader() runs, and refuses ambiguous multi-login scopes safely", async () => {
    const { default: pluginExport } = await import("../index.mjs");
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agy2api-cold-auth-"));
    try {
      // 1. Single primary "agy2api" login in plugin-auth.json (container URL http://agy2api.internal:8017)
      fs.writeFileSync(
        path.join(tmpDir, "plugin-auth.json"),
        JSON.stringify({
          agy2api: {
            type: "api",
            key: "sk-cold-single",
            metadata: {
              baseUrl: "http://agy2api.internal:8017",
              adminUsername: "admin",
              adminPassword: "pw1",
            },
          },
          "other-provider#abc": { type: "api", key: "sk-other" },
        }),
      );

      // Simulate cold Bun host startup: server() + config() + unauthenticated provider.models({}, {}) run BEFORE loader()!
      const hooks = await pluginExport.server(
        { directory: tmpDir, magpie: { options: async () => ({ preserve_cache_effort: true }) } },
        { disablePageService: true },
      );
      await hooks.config({});
      await hooks.provider.models({ models: {} }, { fetchImpl: async () => new Response("nope", { status: 500 }) }).catch(() => null);

      const seenUrls = [];
      const mockCatalogFetch = async (url, init) => {
        const u = String(url);
        seenUrls.push({ url: u, auth: new Headers(init?.headers).get("authorization") });
        if (u === "http://agy2api.internal:8017/api/session") {
          return new Response("{}", {
            status: 200,
            headers: { "set-cookie": "antigravity_admin=sess1; Path=/; HttpOnly" },
          });
        }
        if (u === "http://agy2api.internal:8017/api/models") {
          return new Response(
            JSON.stringify({
              models: [
                {
                  id: "gemini-3.8-flash",
                  name: "Gemini 3.8 Flash",
                  provider: "MODEL_PROVIDER_GOOGLE",
                  quota_group: "gemini",
                  input_token_limit: 1_048_576,
                  output_token_limit: 65_536,
                  thinking_levels: ["low", "medium", "high"],
                  capabilities: { thinking: true, images: true },
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (u === "http://agy2api.internal:8017/api/settings") {
          return new Response(JSON.stringify({ values: {} }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        throw new Error(`Unexpected fetch URL: ${u}`);
      };

      const firstColdOut = await hookOnRequest(
        {
          model: "agy2api/claude-sonnet-5-5",
          max_tokens: 128,
          metadata: { purpose: "project_memory_extract" },
          messages: [{ role: "user", content: "Reply OK" }],
          thinking: { type: "adaptive" },
          output_config: { effort: "high" },
        },
        {
          protocol: "anthropic",
          session: "cold-sess-1",
          path: "/v1/messages",
          fetchImpl: mockCatalogFetch,
          options: {
            relaySecret: TEST_SECRET,
            auxIncompatiblePolicy: "fallback_model",
            auxFallbackModel: "gemini-3.8-flash",
            auxFallbackEffort: "low",
          },
        },
      );
      assert.ok(firstColdOut?.[RELAY_FIELD], "first cold request must switch to fallback_model without loader()");
      assert.equal(getAuxRoutingDiagnostics().at(-1).routedModel, "gemini-3.8-flash");
      assert.ok(seenUrls.some((x) => x.url === "http://agy2api.internal:8017/api/models"));

      // 1b. Adding a second login immediately invalidates single-login cache (0 ms stale window) and reports auth_scope_ambiguous even without relaySecret!
      fs.writeFileSync(
        path.join(tmpDir, "plugin-auth.json"),
        JSON.stringify({
          agy2api: {
            type: "api",
            key: "sk-cold-single",
            metadata: { baseUrl: "http://agy2api.internal:8017" },
          },
          "agy2api#second": {
            type: "api",
            key: "sk-second",
            metadata: { baseUrl: "http://agy2api2.internal:8017" },
          },
        }),
      );
      const immAmbigOut = await hookOnRequest(
        {
          model: "agy2api/claude-sonnet-5-5",
          max_tokens: 128,
          metadata: { purpose: "project_memory_extract" },
          messages: [{ role: "user", content: "Reply OK" }],
          output_config: { effort: "high" },
        },
        {
          protocol: "anthropic",
          session: "cold-sess-imm-ambig",
          path: "/v1/messages",
          options: {
            auxIncompatiblePolicy: "fallback_model",
            auxFallbackModel: "gemini-3.8-flash",
            auxFallbackEffort: "low",
          },
        },
      );
      assert.equal(RELAY_FIELD in immAmbigOut, false);
      assert.equal(getAuxRoutingDiagnostics().at(-1).fallbackRejectedReason, "auth_scope_ambiguous");

      // 1c. plugins.json explicit preserveCacheEffort:false is NOT masked by host.js synthesized default true when settings.json has no UI override
      fs.writeFileSync(path.join(tmpDir, "settings.json"), JSON.stringify({ pluginOptions: {} }));
      fs.writeFileSync(
        path.join(tmpDir, "plugins.json"),
        JSON.stringify({
          plugins: [{ spec: "magpie-agy2api-plugin", options: { preserveCacheEffort: false } }],
        }),
      );
      const hooksOff = await pluginExport.server(
        { directory: tmpDir, magpie: { options: async () => ({ preserve_cache_effort: false }) } },
        { disablePageService: true, preserveCacheEffort: false },
      );
      assert.equal(
        hooksOff.auth.options.find((o) => o.key === "preserve_cache_effort").default,
        false,
      );
      // Even if a mock magpie.options returns synthesized true while settings.json has no chosen value, diskOpts wins
      setPluginRuntimeContext({ directory: tmpDir, magpie: { options: async () => ({ preserve_cache_effort: true }) } });
      const offCheck = await hookOnRequest(
        {
          model: "agy2api/claude-sonnet-5-5",
          max_tokens: 128,
          metadata: { purpose: "project_memory_extract" },
          messages: [{ role: "user", content: "Reply OK" }],
          output_config: { effort: "high" },
        },
        { protocol: "anthropic", session: "cold-sess-off", path: "/v1/messages", nowFn: () => Date.now() + 2000 },
      );
      assert.equal(offCheck, undefined);
      fs.rmSync(path.join(tmpDir, "settings.json"), { force: true });
      fs.rmSync(path.join(tmpDir, "plugins.json"), { force: true });

      // 2. Single suffixed "agy2api#x9k2m1" in plugin-auth.json.bak when primary is corrupt
      resetAllState();
      fs.writeFileSync(path.join(tmpDir, "plugin-auth.json"), "{corrupt-json");
      fs.writeFileSync(
        path.join(tmpDir, "plugin-auth.json.bak"),
        JSON.stringify({
          "agy2api#x9k2m1": {
            type: "api",
            key: "sk-suffixed-only",
            metadata: { baseUrl: "http://agy2api-bak.internal:8017" },
          },
        }),
      );
      const hooks2 = await pluginExport.server(
        { directory: tmpDir, magpie: null },
        { disablePageService: true },
      );
      await hooks2.config({});
      let sawBakUrl = false;
      const bakOut = await hookOnRequest(
        {
          model: "agy2api/claude-sonnet-5-5",
          max_tokens: 128,
          metadata: { purpose: "project_memory_extract" },
          messages: [{ role: "user", content: "Reply OK" }],
          output_config: { effort: "high" },
        },
        {
          protocol: "anthropic",
          session: "cold-sess-2",
          path: "/v1/messages",
          nowFn: () => Date.now() + 5000,
          fetchImpl: async (url) => {
            const u = String(url);
            if (u.startsWith("http://agy2api-bak.internal:8017")) sawBakUrl = true;
            if (u.endsWith("/api/models")) {
              return new Response(
                JSON.stringify({
                  models: [
                    {
                      id: "gemini-3.8-flash",
                      name: "Gemini 3.8 Flash",
                      provider: "MODEL_PROVIDER_GOOGLE",
                      quota_group: "gemini",
                      input_token_limit: 1_048_576,
                      thinking_levels: ["low", "high"],
                      capabilities: { thinking: true },
                    },
                  ],
                }),
                { status: 200, headers: { "content-type": "application/json" } },
              );
            }
            return new Response(JSON.stringify({ values: {} }), { status: 200 });
          },
          options: {
            relaySecret: TEST_SECRET,
            auxIncompatiblePolicy: "fallback_model",
            auxFallbackModel: "gemini-3.8-flash",
            auxFallbackEffort: "low",
          },
        },
      );
      assert.equal(sawBakUrl, true);
      assert.ok(bakOut?.[RELAY_FIELD]);

      // 3. Multi-login ambiguity ("agy2api" + "agy2api#team2"): MUST NOT pick either account, safely falls back to current_low!
      resetAllState();
      fs.writeFileSync(
        path.join(tmpDir, "plugin-auth.json"),
        JSON.stringify({
          agy2api: {
            type: "api",
            key: "sk-acc-1",
            metadata: { baseUrl: "http://acc1.internal:8017" },
          },
          "agy2api#team2": {
            type: "api",
            key: "sk-acc-2",
            metadata: { baseUrl: "http://acc2.internal:8017" },
          },
        }),
      );
      const hooks3 = await pluginExport.server(
        { directory: tmpDir, magpie: null },
        { disablePageService: true },
      );
      await hooks3.config({});
      let touchedAnyAccount = false;
      const ambigOut = await hookOnRequest(
        {
          model: "agy2api/claude-sonnet-5-5",
          max_tokens: 128,
          metadata: { purpose: "project_memory_extract" },
          messages: [{ role: "user", content: "Reply OK" }],
          output_config: { effort: "high" },
        },
        {
          protocol: "anthropic",
          session: "cold-sess-ambig",
          path: "/v1/messages",
          nowFn: () => Date.now() + 10_000,
          fetchImpl: async () => {
            touchedAnyAccount = true;
            throw new Error("Must not probe any account when scope is ambiguous");
          },
          options: {
            relaySecret: TEST_SECRET,
            auxIncompatiblePolicy: "fallback_model",
            auxFallbackModel: "gemini-3.8-flash",
            auxFallbackEffort: "low",
          },
        },
      );
      assert.equal(touchedAnyAccount, false);
      assert.equal(RELAY_FIELD in ambigOut, false);
      assert.equal(ambigOut.output_config.effort, "low");
      const ambigDiag = getAuxRoutingDiagnostics().at(-1);
      assert.equal(ambigDiag.policy, "current_low");
      assert.equal(ambigDiag.fallbackRejectedReason, "auth_scope_ambiguous");
      assert.equal(ambigDiag.sessionIsolated, true);

      // 4. Over-6MB body when scope is ambiguous still reports auth_scope_ambiguous before payload_too_large
      const over6MbAmbig = await hookOnRequest(
        {
          model: "agy2api/claude-sonnet-5-5",
          max_tokens: 128,
          metadata: { purpose: "project_memory_extract" },
          messages: [{ role: "user", content: "Z".repeat(6 * 1024 * 1024 + 256) }],
          output_config: { effort: "high" },
        },
        {
          protocol: "anthropic",
          session: "cold-sess-ambig-big",
          path: "/v1/messages",
          options: {
            relaySecret: TEST_SECRET,
            auxIncompatiblePolicy: "fallback_model",
            auxFallbackModel: "gemini-3.8-flash",
            auxFallbackEffort: "low",
          },
        },
      );
      assert.equal(RELAY_FIELD in over6MbAmbig, false);
      assert.equal(getAuxRoutingDiagnostics().at(-1).fallbackRejectedReason, "auth_scope_ambiguous");

      // 5. Memory vs single-disk conflict returns null, and subsequent registerAuthScope retains sticky ambiguity
      resetAllState();
      fs.writeFileSync(
        path.join(tmpDir, "plugin-auth.json"),
        JSON.stringify({
          agy2api: {
            type: "api",
            key: "sk-disk-only",
            metadata: { baseUrl: "http://disk.internal:8017" },
          },
        }),
      );
      setPluginRuntimeContext({ directory: tmpDir });
      registerAuthScope({ baseUrl: "http://mem-conflict.internal:8017", apiKey: "sk-mem-other" });
      assert.equal(getRegisteredAuthScope(), null, "memory vs disk credential conflict must return null");
      registerAuthScope({ baseUrl: "http://disk.internal:8017", apiKey: "sk-disk-only" });
      assert.equal(getRegisteredAuthScope(), null, "subsequent registration must retain sticky authScopeAmbiguous");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
