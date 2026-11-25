import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { onRequest as hookOnRequest, onResponse as hookOnResponse } from "../hooks.mjs";
import * as middlewareMod from "../middleware.mjs";
import { onRequest as mwOnRequest } from "../middleware.mjs";
import { sanitizeRequestBody } from "../lib/sanitize-request.mjs";
import { RECOMMENDED_PRESET_RULES, SIDELOAD_OPEN_TAG } from "../lib/sanitizer.mjs";
import plugin from "../index.mjs";
import { clearAdminSessionCache } from "../lib/auth.mjs";
import { createAgy2ApiFetch, clearPrefixEffortCache } from "../lib/fetch.mjs";
import { buildModelsFromRawEntries, clearModelCache, ensureModelsDiscovered } from "../lib/models.mjs";
import { clearQuotaCache, computeAgy2ApiUsage } from "../lib/quota.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.resolve(__dirname, "..");

const LARGE_PADDING = "A".repeat(36 * 1024);

function makeCtx(protocol, providerId = "agy2api", model = "gemini-4-neon") {
  return {
    protocol,
    model,
    stream: true,
    path: protocol === "gemini" ? `/v1beta/models/${model}:streamGenerateContent` : `/v1/${protocol}`,
    options: {},
    state: {},
    provider: {
      id: providerId,
      name: "Antigravity2API",
      model,
    },
  };
}

describe("Integration: Single-pass PromptSanitizer + preserve_cache_effort in agy2apiFetch", () => {
  beforeEach(() => {
    clearPrefixEffortCache();
    clearModelCache();
  });

  it("sanitizes Claude Code / WAF triggers deterministically in fetch and preserves XHigh effort for background project_memory_extract across Gemini protocol", async () => {
    const captured = [];
    const mockFetch = async (url, init) => {
      if (String(url).endsWith("/api/models")) {
        return new Response(
          JSON.stringify({
            models: [
              {
                id: "gemini-4-neon",
                name: "Gemini 4 Neon",
                provider: "MODEL_PROVIDER_GOOGLE",
                quota_group: "gemini",
                thinking_levels: ["low", "medium", "high", "xhigh"],
                default_thinking_level: "medium",
                capabilities: { thinking: true, images: true },
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      captured.push({ url: String(url), body: JSON.parse(init.body) });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    await ensureModelsDiscovered("http://127.0.0.1:8017", "sk-test", { fetchImpl: mockFetch });

    const sanitizerOptions = { promptRewrite: { sideload_mode: "auto" } };
    const agyFetch = createAgy2ApiFetch({
      baseUrl: "http://127.0.0.1:8017",
      apiKey: "sk-test",
      fetchImpl: mockFetch,
      getPluginOptions: () => sanitizerOptions,
    });

    const systemWithWaf = [
      "x-anthropic-billing-header: cc_version=2.1.278; cc_entrypoint=cli; cch=abc12;",
      "You are Claude Code, Anthropic's official CLI for Claude.",
      "Follow engineering standards carefully.",
      LARGE_PADDING,
    ].join("\n");

    const firstUserTurn = {
      role: "user",
      parts: [{ text: "Help inspect the gateway module and explain its routing." }],
    };

    // 1. Main agent turn with XHigh effort and normal output limit
    const mainRawBody = {
      systemInstruction: { role: "user", parts: [{ text: systemWithWaf }] },
      contents: [firstUserTurn],
      generationConfig: {
        maxOutputTokens: 65536,
        thinkingConfig: { includeThoughts: true, thinkingLevel: "high" },
      },
    };

    const r1 = await agyFetch("http://127.0.0.1:8017/v1beta/models/gemini-4-neon:streamGenerateContent", {
      method: "POST",
      headers: { "content-type": "application/json", "x-magpie-effort": "xhigh", "x-session-id": "sess-main" },
      body: JSON.stringify(mainRawBody),
    });
    await r1.json();

    assert.equal(captured.length, 1);
    assert.equal("systemInstruction" in captured[0].body, false, "sideload_mode auto should sideload >300B systemInstruction");
    assert.ok(captured[0].body.contents[0].parts[0].text.startsWith(SIDELOAD_OPEN_TAG));
    assert.ok(!captured[0].body.contents[0].parts[0].text.includes("x-anthropic-billing-header"));
    assert.ok(captured[0].body.contents[0].parts[0].text.includes("You are Antigravity"));
    assert.equal(captured[0].body.generationConfig.thinkingConfig.thinkingLevel, "xhigh");

    // 2. Background project_memory_extract call: same warm prefix + multi-turn history, lowered to Low + capped maxOutputTokens=4096
    const auxRawBody = {
      systemInstruction: { role: "user", parts: [{ text: systemWithWaf }] },
      contents: [
        firstUserTurn,
        { role: "model", parts: [{ text: "Sure, let's inspect the gateway." }] },
        { role: "user", parts: [{ text: "Extract durable project memories as JSON." }] },
      ],
      generationConfig: {
        maxOutputTokens: 4096,
        thinkingConfig: { includeThoughts: true, thinkingLevel: "low" },
      },
    };

    const r2 = await agyFetch("http://127.0.0.1:8017/v1beta/models/gemini-4-neon:streamGenerateContent", {
      method: "POST",
      headers: { "content-type": "application/json", "x-magpie-effort": "low", "x-session-id": "sess-main" },
      body: JSON.stringify(auxRawBody),
    });
    await r2.json();

    assert.equal(captured.length, 2);
    assert.equal(captured[1].body.systemInstruction, captured[0].body.systemInstruction);
    assert.deepEqual(captured[1].body.contents[0], captured[0].body.contents[0]);
    assert.equal(
      captured[1].body.generationConfig.thinkingConfig.thinkingLevel,
      "xhigh",
      "background memory extraction downgrade should restore XHigh effort",
    );

    // 3. User actively switches main session to Medium (full maxOutputTokens=65536, identical sanitizerOptions) -> MUST take effect!
    const userSwitchMediumBody = {
      systemInstruction: { role: "user", parts: [{ text: systemWithWaf }] },
      contents: [
        firstUserTurn,
        { role: "model", parts: [{ text: "Sure, let's inspect the gateway." }] },
        { role: "user", parts: [{ text: "Now summarize briefly with medium effort." }] },
      ],
      generationConfig: {
        maxOutputTokens: 65536,
        thinkingConfig: { includeThoughts: true, thinkingLevel: "medium" },
      },
    };
    const r3 = await agyFetch("http://127.0.0.1:8017/v1beta/models/gemini-4-neon:streamGenerateContent", {
      method: "POST",
      headers: { "content-type": "application/json", "x-magpie-effort": "medium", "x-session-id": "sess-main" },
      body: JSON.stringify(userSwitchMediumBody),
    });
    await r3.json();

    assert.equal(captured.length, 3);
    assert.deepEqual(captured[2].body.contents[0], captured[0].body.contents[0]);
    assert.equal(
      captured[2].body.generationConfig.thinkingConfig.thinkingLevel,
      "medium",
      "explicit user switch to Medium with normal output budget must take effect",
    );

    // 4. Subsequent Low aux call in same session aligns to updated Medium (NOT stale XHigh, NOT raw Low)
    const r4 = await agyFetch("http://127.0.0.1:8017/v1beta/models/gemini-4-neon:streamGenerateContent", {
      method: "POST",
      headers: { "content-type": "application/json", "x-magpie-effort": "low", "x-session-id": "sess-main" },
      body: JSON.stringify(auxRawBody),
    });
    await r4.json();
    assert.equal(captured.length, 4);
    assert.equal(captured[3].body.generationConfig.thinkingConfig.thinkingLevel, "medium");

    // 5. Independent session with identical first user turn & system but different session ID stays Low
    const indRawBody = {
      systemInstruction: { role: "user", parts: [{ text: systemWithWaf }] },
      contents: [
        firstUserTurn,
        { role: "model", parts: [{ text: "Initial." }] },
        { role: "user", parts: [{ text: "Extract." }] },
      ],
      generationConfig: {
        maxOutputTokens: 4096,
        thinkingConfig: { includeThoughts: true, thinkingLevel: "low" },
      },
    };
    const r5 = await agyFetch("http://127.0.0.1:8017/v1beta/models/gemini-4-neon:streamGenerateContent", {
      method: "POST",
      headers: { "content-type": "application/json", "x-magpie-effort": "low", "x-session-id": "sess-other" },
      body: JSON.stringify(indRawBody),
    });
    await r5.json();

    assert.equal(captured.length, 5);
    assert.equal(captured[4].body.generationConfig.thinkingConfig.thinkingLevel, "low");
  });

  it("works end-to-end across Anthropic Messages protocol with sanitized system blocks, format, and cache_control preserved", async () => {
    const captured = [];
    const mockFetch = async (url, init) => {
      captured.push({ url: String(url), body: JSON.parse(init.body) });
      return new Response(JSON.stringify({ id: "msg_1", type: "message" }), { status: 200 });
    };

    const agyFetch = createAgy2ApiFetch({
      baseUrl: "http://127.0.0.1:8017",
      apiKey: "sk-test",
      fetchImpl: mockFetch,
      getPluginOptions: () => ({ promptRewrite: { sideload_mode: "auto" } }),
    });

    const systemBlocks = [
      { type: "text", text: "x-anthropic-billing-header: cc_version=2.1.278;" },
      {
        type: "text",
        text: `You are an interactive agent that helps users with software engineering tasks.\n${LARGE_PADDING}`,
        cache_control: { type: "ephemeral" },
      },
    ];
    const msg0 = { role: "user", content: "Inspect the plugin architecture." };

    const mainBody = {
      model: "claude-opus-5-5",
      max_tokens: 64000,
      system: systemBlocks,
      messages: [msg0],
      thinking: { type: "adaptive" },
      output_config: { effort: "high" },
    };

    await agyFetch("http://127.0.0.1:8017/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-magpie-effort": "high", "x-session-id": "anth-sess-1" },
      body: JSON.stringify(mainBody),
    });

    assert.equal("system" in captured[0].body, false, "sideload_mode auto should sideload >300B Anthropic system");
    assert.ok(captured[0].body.messages[0].content[0].text.startsWith(SIDELOAD_OPEN_TAG));
    assert.equal(captured[0].body.messages[0].content[1].text, "Inspect the plugin architecture.");

    const auxBody = {
      model: "claude-opus-5-5",
      max_tokens: 4096,
      system: systemBlocks,
      messages: [
        msg0,
        { role: "assistant", content: "I checked it." },
        { role: "user", content: "Extract memory." },
      ],
      thinking: { type: "adaptive" },
      output_config: { effort: "low", format: { type: "json_schema", schema: { type: "object" } } },
    };
    await agyFetch("http://127.0.0.1:8017/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-magpie-effort": "low", "x-session-id": "anth-sess-1" },
      body: JSON.stringify(auxBody),
    });

    assert.equal(captured[1].body.system, captured[0].body.system);
    assert.deepEqual(captured[1].body.messages[0], captured[0].body.messages[0]);
    assert.equal(captured[0].body.output_config.effort, "high");
    assert.equal(captured[1].body.output_config.effort, "high");
    assert.deepEqual(captured[1].body.output_config.format, {
      type: "json_schema",
      schema: { type: "object" },
    });
  });

  it("composes config -> provider.models -> auth.loader -> chat.headers -> fetch -> auth.usage cleanly without page service", async () => {
    clearAdminSessionCache();
    clearModelCache();
    clearQuotaCache();
    clearPrefixEffortCache();

    let uiFold = false;
    let uiShowDetails = true;
    const upstreamRequests = [];
    const origFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      const u = new URL(url);
      const headers = new Headers(init?.headers);
      if (u.pathname === "/subpath/api/models") {
        return new Response(
          JSON.stringify({
            models: [
              {
                id: "gemini-fixture",
                name: "Gemini Fixture",
                provider: "MODEL_PROVIDER_GOOGLE",
                quota_group: "gemini",
                thinking_levels: ["low", "high"],
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (u.pathname === "/subpath/api/accounts") {
        return new Response(
          JSON.stringify({
            accounts: [
              {
                id: "fixture@example.com",
                label: "Fixture",
                state: "ready",
                tier: "g1-pro-tier",
                quota: [{ bucket_id: "gemini-5h", window: "5h", remaining_fraction: 0.75 }],
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (u.pathname === "/subpath/v1/messages") {
        upstreamRequests.push({
          url: String(url),
          headers,
          body: JSON.parse(init.body),
        });
        return new Response(JSON.stringify({ id: "msg_ok", type: "message" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected upstream URL: ${url}`);
    };

    try {
      const hooks = await plugin.server(
        {
          magpie: {
            options: () => ({
              fold_effort_variants: uiFold,
              show_account_details: uiShowDetails,
              refresh_on_usage: false,
            }),
          },
        },
        { disablePageService: true, promptSanitizer: true },
      );

      const cfg = {
        provider: {
          agy2api: { api: "https://composed.example.invalid/subpath/v1beta" },
        },
      };
      await hooks.config(cfg);

      const modelsUnfolded = await hooks.provider.models(cfg.provider.agy2api, {
        auth: { key: "sk-composed" },
      });
      assert.ok(modelsUnfolded["gemini-fixture"]);
      assert.ok(modelsUnfolded["gemini-fixture-high"]);

      const loaded = await hooks.auth.loader(
        async () => ({ key: "sk-composed" }),
        cfg.provider.agy2api,
      );
      assert.equal(loaded.baseURL, "https://composed.example.invalid/subpath");

      const chatOut = { headers: {} };
      await hooks["chat.headers"](
        { model: { providerID: "agy2api" }, sessionID: "magpie-sess-99" },
        chatOut,
      );
      assert.ok(chatOut.headers["x-agy2api-cache-session"]);

      await loaded.fetch("https://composed.example.invalid/subpath/v1/messages", {
        method: "POST",
        headers: { ...chatOut.headers, "content-type": "application/json" },
        body: JSON.stringify({
          model: "claude-opus-5-5",
          max_tokens: 4096,
          system: [
            { type: "text", text: "x-anthropic-billing-header: cc_version=2.1;" },
            { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
          ],
          messages: [{ role: "user", content: "hello" }],
        }),
      });
      assert.equal(upstreamRequests.length, 1);
      assert.equal(upstreamRequests[0].headers.get("x-agy2api-cache-session"), null);
      assert.equal(
        JSON.stringify(upstreamRequests[0].body).includes("x-anthropic-billing-header"),
        false,
      );
      assert.equal(
        JSON.stringify(upstreamRequests[0].body).includes("You are Antigravity"),
        true,
      );

      uiFold = true;
      uiShowDetails = false;
      const modelsFolded = await hooks.provider.models(cfg.provider.agy2api, {
        auth: { key: "sk-composed" },
      });
      assert.equal(modelsFolded["gemini-fixture-high"], undefined);

      const usage = await hooks.auth.usage(
        async () => ({ key: "sk-composed" }),
        { ...cfg.provider.agy2api, models: modelsFolded },
      );
      assert.equal(usage.plan, "PRO ×1");
      assert.equal(
        usage.windows.some((w) => w.name.includes("Fixture · PRO")),
        false,
      );
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("includes derived effort model IDs on folded base usage windows so effort-suffixed calls still match pool quota", () => {
    const raw = new Map([
      [
        "gemini-4-argon",
        {
          id: "gemini-4-argon",
          name: "Gemini 4 Argon",
          provider: "MODEL_PROVIDER_GOOGLE",
          quota_group: "gemini-argon-wtu",
          thinking_levels: ["low", "medium", "high"],
          default_thinking_level: "medium",
        },
      ],
    ]);
    const built = buildModelsFromRawEntries(raw, "http://127.0.0.1:8017", {
      foldEffortVariants: true,
    });
    const usage = computeAgy2ApiUsage(
      [
        {
          id: "alice@example.com",
          state: "ready",
          tier: "g1-pro-tier",
          quota_at: "2026-11-22T12:00:00Z",
          quota: [
            {
              bucket_id: "gemini-argon-wtu-weekly",
              window: "weekly",
              remaining_fraction: 0,
              reset_time: "2026-11-29T00:00:00Z",
            },
          ],
        },
      ],
      {
        foldEffortVariants: true,
        discoveredModels: built.models,
        modelQuotaGroupMap: built.modelQuotaGroupMap,
        modelMetadataMap: built.modelMetadataMap,
        nowMs: Date.parse("2026-11-22T12:00:00Z"),
      },
    );

    const argonWin = usage.windows.find((w) => !w.aside && w.model === "gemini-4-argon");
    assert.ok(argonWin, "should emit non-aside window for gemini-4-argon");
    assert.equal(argonWin.used, 100);
    assert.deepEqual(argonWin.models, [
      "gemini-4-argon",
      "gemini-4-argon-low",
      "gemini-4-argon-medium",
      "gemini-4-argon-high",
    ]);
  });

  it("preserves OpenAI Chat role:tool and role:function outputs byte-identically even when containing WAF literals", () => {
    const rawToolOutput = [
      'const BILLING = "x-anthropic-billing-header:";',
      'const SDK = "You are a Claude agent, built on Anthropic\'s Claude Agent SDK.";',
      'const CODEX = "as Codex:";',
      "const mode = 'codemode';",
    ].join("\n");

    const body = {
      model: "gemini-4-neon",
      messages: [
        { role: "system", content: "You are Claude Code, Anthropic's official CLI for Claude." },
        { role: "user", content: "Read sanitizer.mjs" },
        {
          role: "assistant",
          content: null,
          tool_calls: [{ id: "call_1", type: "function", function: { name: "Read", arguments: "{}" } }],
        },
        { role: "tool", tool_call_id: "call_1", content: rawToolOutput },
      ],
    };

    const sanitized = sanitizeRequestBody("chat", body, {});
    assert.ok(sanitized);
    assert.ok(sanitized.messages[0].content.includes("You are Antigravity"));
    assert.equal(
      sanitized.messages[3].content,
      rawToolOutput,
      "role:tool file contents must never be altered by PromptSanitizer",
    );
  });

  it("declares a dedicated Magpie sidebar page (not a provider panel) matching pageinline/CSP rules and exact 12 preset rules", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(PLUGIN_ROOT, "package.json"), "utf8"));
    assert.equal(pkg.magpie?.panels, undefined, "provider-slot panels must be removed");
    assert.equal(pkg.magpie?.actions, undefined, "no right-click actions for other providers");
    const page = pkg.magpie?.page;
    assert.ok(page && typeof page === "object" && !Array.isArray(page));
    assert.equal(page.title, "Prompt Sanitizer");
    assert.equal(page.file, "ui/sanitizer-panel.html");
    assert.equal(page.icon, "ui/icon.svg");
    assert.equal(page.titles?.zh, "风控提示词清洗");

    const iconPath = path.join(PLUGIN_ROOT, page.icon);
    assert.ok(fs.existsSync(iconPath), "sidebar icon must exist");
    const icon = fs.readFileSync(iconPath, "utf8");
    assert.ok(/^\s*<svg\b[^>]*xmlns="http:\/\/www\.w3\.org\/2000\/svg"/.test(icon), "icon must be an SVG root element");
    assert.ok(/<\/svg>\s*$/.test(icon));
    assert.ok(/viewBox="0 0 16 16"/.test(icon));
    assert.ok(/stroke="currentColor"/.test(icon) && /fill="none"/.test(icon), "icon must be monochrome currentColor");
    assert.ok(!/<script|\son[a-z]+\s*=|url\s*\(/i.test(icon), "icon must be inert");

    const html = fs.readFileSync(path.join(PLUGIN_ROOT, "ui/sanitizer-panel.html"), "utf8");
    const css = fs.readFileSync(path.join(PLUGIN_ROOT, "ui/sanitizer-panel.css"), "utf8");
    const js = fs.readFileSync(path.join(PLUGIN_ROOT, "ui/sanitizer-panel.js"), "utf8");

    assert.ok(html.includes('<script src="_magpie/bridge.js"></script>'));
    assert.ok(html.includes('<script src="sanitizer-panel.js" defer></script>'));
    assert.ok(!/type\s*=\s*["']module["']/i.test(html), "page must use classic scripts for pageinline.go");
    assert.ok(!/\son[a-z]+\s*=/i.test(html), "page HTML must not contain inline event handlers");
    assert.ok(!/url\s*\(/i.test(css), "page CSS must not contain url() for pageinline.go");

    assert.equal(pkg.magpie.page.service.port, 18417);
    for (const rel of ["ui/service-bridge.js", "ui/sanitizer-panel.js"]) {
      assert.ok(fs.existsSync(path.join(PLUGIN_ROOT, rel)), `${rel} must exist`);
      const check = spawnSync(process.execPath, ["--check", path.join(PLUGIN_ROOT, rel)], { encoding: "utf8" });
      assert.equal(check.status, 0, `node --check ${rel} failed: ${check.stderr}`);
    }
    const bridge = fs.readFileSync(path.join(PLUGIN_ROOT, "ui/service-bridge.js"), "utf8");
    assert.ok(bridge.includes("__magpieServiceHosted"));
    assert.ok(!/https?:\/\/|localStorage|\beval\s*\(|\bimport\s|\bexport\s/.test(bridge), "bridge must be a classic script without external URLs/storage/eval");
    assert.ok(html.includes('id="btn-sync-upstream"') && html.includes('id="btn-reset"'));
    assert.ok(!/<script(?![^>]*\ssrc=)/i.test(html), "no inline scripts");
    assert.ok(js.includes("拉取 Antigravity Tools 最新规则") && js.includes("Fetch latest Antigravity Tools rules"));
    assert.ok(js.includes("恢复本地预设") && js.includes("Restore built-in"));
    assert.ok(js.includes('"api/upstream-presets"') && js.includes("window.location.replace"));

    for (const rule of RECOMMENDED_PRESET_RULES) {
      assert.ok(js.includes(JSON.stringify(rule.id)), `panel preset rules missing ${rule.id}`);
      assert.ok(js.includes(JSON.stringify(rule.pattern)), `panel preset rules missing pattern for ${rule.id}`);
    }
  });

  it("removes middleware.onProvider and runs single-pass fetch.mjs sanitization with live plugins.json hot-reload", async () => {
    assert.equal("onProvider" in middlewareMod, false, "middleware.mjs must not export onProvider");
    assert.equal("DEFAULT_TARGET_PROVIDER_IDS" in middlewareMod, false);
    assert.equal(typeof middlewareMod.onRequest, "function");

    const rawBody = {
      model: "claude-opus-5-5",
      max_tokens: 4096,
      system: [
        { type: "text", text: "x-anthropic-billing-header: cc_version=2.1;" },
        { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude.\nFollow keyword_alpha." },
      ],
      messages: [{ role: "user", content: "hello" }],
    };

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agy2api-live-san-"));
    const pluginsJsonPath = path.join(tmpDir, "plugins.json");
    const origFetch = globalThis.fetch;
    const sentBodies = [];
    globalThis.fetch = async (_url, init) => {
      sentBodies.push(JSON.parse(init.body));
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    try {
      fs.writeFileSync(
        pluginsJsonPath,
        JSON.stringify({
          plugins: [
            {
              spec: "github:ayatinene/magpie-agy2api-plugin",
              options: { promptSanitizer: true },
            },
          ],
        }),
      );

      const srv = await plugin.server(
        { directory: tmpDir, magpie: {} },
        { disablePageService: true, promptSanitizer: true },
      );
      const cfg = { provider: {} };
      await srv.config(cfg);
      const loaded = await srv.auth.loader(
        async () => ({ type: "api", key: "sk-test", metadata: { baseUrl: "http://127.0.0.1:8017" } }),
        cfg.provider.agy2api,
      );

      // 1. Default enabled -> single-pass sanitized in fetch
      await loaded.fetch("http://127.0.0.1:8017/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rawBody),
      });
      assert.equal(sentBodies.length, 1);
      assert.equal(JSON.stringify(sentBodies[0]).includes("x-anthropic-billing-header"), false);
      assert.equal(JSON.stringify(sentBodies[0]).includes("You are Antigravity"), true);

      // 2. Hot-reload plugins.json (past 1s stat cache window) to disable sanitizer without restarting server()
      await new Promise((r) => setTimeout(r, 1050));
      fs.writeFileSync(
        pluginsJsonPath,
        JSON.stringify({
          plugins: [
            {
              spec: "github:ayatinene/magpie-agy2api-plugin",
              options: { promptSanitizer: false },
            },
          ],
        }),
      );

      await loaded.fetch("http://127.0.0.1:8017/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rawBody),
      });
      assert.equal(sentBodies.length, 2);
      assert.equal(JSON.stringify(sentBodies[1]).includes("You are Claude Code"), true);

      // 3. Hot-reload custom rewrite rule in plugins.json -> immediately applied on next request
      await new Promise((r) => setTimeout(r, 1050));
      fs.writeFileSync(
        pluginsJsonPath,
        JSON.stringify({
          plugins: [
            {
              spec: "github:ayatinene/magpie-agy2api-plugin",
              options: {
                promptSanitizer: true,
                promptRewrite: {
                  enabled: true,
                  normalize_identity: true,
                  sideload_mode: "off",
                  rules: [
                    {
                      id: "r1",
                      pattern: "*keyword_alpha*",
                      replacement: "Follow keyword_beta.",
                      scope: "prompt",
                      enabled: true,
                    },
                  ],
                },
              },
            },
          ],
        }),
      );

      await loaded.fetch("http://127.0.0.1:8017/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rawBody),
      });
      assert.equal(sentBodies.length, 3);
      assert.equal(JSON.stringify(sentBodies[2]).includes("keyword_beta"), true);
    } finally {
      globalThis.fetch = origFetch;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("wires hooks.mjs in package.json and completes hooks.onRequest -> middleware.onRequest -> agy2apiFetch -> hooks.onResponse end-to-end", async () => {
    clearPrefixEffortCache();
    clearModelCache();

    const pkg = JSON.parse(fs.readFileSync(path.join(PLUGIN_ROOT, "package.json"), "utf8"));
    assert.equal(pkg.magpie?.hooks, "./hooks.mjs");
    assert.equal(pkg.magpie?.options?.auxIncompatiblePolicy, "current_low");
    assert.equal(pkg.magpie?.options?.auxFallbackModel, "");
    assert.equal(pkg.magpie?.options?.auxFallbackEffort, "low");
    assert.equal(pkg.magpie?.options?.auxMinBodyBytes, 32768);
    assert.equal(pkg.magpie?.options?.auxMaxOutputTokens, 8192);
    assert.equal(pkg.magpie?.options?.auxSessionTtlSec, 600);

    const relaySecret = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const upstreamSent = [];
    const mockFetch = async (url, init) => {
      if (String(url).endsWith("/api/models")) {
        return new Response(
          JSON.stringify({
            models: [
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
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      upstreamSent.push({
        url: String(url),
        headers: new Headers(init.headers),
        body: JSON.parse(init.body),
      });
      return new Response(JSON.stringify({ id: "msg_1", content: [{ type: "text", text: "ok" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    await ensureModelsDiscovered("http://127.0.0.1:8017", "sk-int", { fetchImpl: mockFetch });
    const agyFetch = createAgy2ApiFetch({
      baseUrl: "http://127.0.0.1:8017",
      apiKey: "sk-int",
      fetchImpl: mockFetch,
    });

    const mainBody = {
      model: "claude-opus-5-5",
      max_tokens: 64000,
      system: [{ type: "text", text: `Main instructions\n${LARGE_PADDING}` }],
      messages: [{ role: "user", content: "<system-reminder>Env</system-reminder>\nAnalyze module" }],
      output_config: { effort: "high" },
      metadata: { user_id: '{"session_id":"int-main-1"}' },
    };

    const st = {};
    await hookOnRequest(mainBody, {
      protocol: "anthropic",
      session: "int-main-1",
      path: "/v1/messages",
      state: st,
      options: { relaySecret },
    });
    await agyFetch("http://127.0.0.1:8017/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-session-id": "int-main-1" },
      body: JSON.stringify(mainBody),
    });
    await hookOnResponse({ content: [{ type: "text", text: "Analyzed module." }] }, { success: true, state: st });

    // Incompatible aux call (post-turn-1 reply matches mainState via onResponse fingerprint, m0 stripped <system-reminder>)
    const auxBody = {
      model: "claude-opus-5-5",
      max_tokens: 4096,
      system: mainBody.system,
      messages: [
        { role: "user", content: "Analyze module" },
        { role: "assistant", content: "Analyzed module." },
        { role: "user", content: "Extract memories" },
      ],
      output_config: { effort: "low" },
      metadata: { user_id: '{"session_id":"int-main-1"}' },
    };
    const hookOut = await hookOnRequest(auxBody, {
      protocol: "anthropic",
      session: "int-main-1",
      path: "/v1/messages",
      options: {
        relaySecret,
        auxIncompatiblePolicy: "fallback_model",
        auxFallbackModel: "gemini-3.8-flash",
        auxFallbackEffort: "low",
      },
    });
    assert.ok(hookOut?._agy2api_relay);

    const mwOut = mwOnRequest(hookOut, {
      protocol: "anthropic",
      options: { relaySecret },
    });
    assert.equal(mwOut.model, "agy2api/gemini-3.8-flash");
    assert.equal("_agy2api_relay" in mwOut, false);

    // Simulate Magpie routing agy2api/gemini-3.8-flash -> agy2api provider fetch (bare model)
    await agyFetch("http://127.0.0.1:8017/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-session-id": "int-main-1" },
      body: JSON.stringify({ ...mwOut, model: "gemini-3.8-flash" }),
    });

    assert.equal(upstreamSent.length, 2);
    assert.equal(upstreamSent[1].body.model, "gemini-3.8-flash");
    assert.match(upstreamSent[1].headers.get("x-session-id"), /^agy2api-aux-v1-[0-9a-f]{32}$/);
    assert.match(
      JSON.parse(upstreamSent[1].body.metadata.user_id).session_id,
      /^agy2api-aux-v1-[0-9a-f]{32}$/,
    );
  });
});
