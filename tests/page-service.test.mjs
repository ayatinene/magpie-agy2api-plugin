import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

import {
  DEFAULT_PAGE_SERVICE_PORT,
  MAX_PATTERN_CHARS,
  MAX_REPLACEMENT_CHARS,
  MAX_RULES,
  MAX_UPSTREAM_BODY_BYTES,
  UPSTREAM_AGT_BETA_CONFIG_URL,
  buildHtmlCsp,
  fetchUpstreamPresetRules,
  parseRustPresetRules,
  startPageService,
  stopPageService,
} from "../lib/page-service.mjs";
import { RECOMMENDED_PRESET_RULES } from "../lib/sanitizer.mjs";
import plugin from "../index.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.resolve(__dirname, "..");

async function allocateFreePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.unref();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const addr = probe.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      probe.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

const REAL_AGT_BETA_CONFIG_SNIPPET = `
// Leading comment with braces { not a function }
pub fn unrelated_before() -> &'static str {
    let ch = '{';
    let s = "fake fn recommended_preset_rules() { }";
    "}"
}

/* Nested /* block comment with { braces } */ end */
pub fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
    // Commented out rule should be ignored:
    // PromptRewriteRule::with_scope("ignored", "ignored*", "", PromptRewriteScope::Prompt, true),
    vec![
        PromptRewriteRule::with_scope(
            "preset-opencode",
            "You are an AI agent running in OpenCode*",
            "",
            PromptRewriteScope::Prompt,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-claude-code-agent",
            "You are an interactive agent that helps users with software engineering tasks*",
            "",
            PromptRewriteScope::Prompt,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-opencode-session-move",
            "*tools.opencode.session*move*",
            "tools.opencode.session_relocate",
            PromptRewriteScope::All,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-dsh-identity",
            "You are an AI agent powered by DeepSeek Harness*",
            "",
            PromptRewriteScope::Prompt,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-dsh-model",
            "You are a coding agent powered by *gemini*",
            "",
            PromptRewriteScope::Prompt,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-dsh-browser-context",
            "*The browser provides no implicit DOM, route, or screenshot context*",
            "The browser exposes no DOM tree, route list, or page screenshot context",
            PromptRewriteScope::Prompt,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-workbuddy",
            "*WorkBuddy*",
            "",
            PromptRewriteScope::All,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-workbuddy-powered-by",
            "*This conversation is powered by *",
            "Selected model: ",
            PromptRewriteScope::Prompt,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-codex-desktop-context",
            "*# Codex desktop context*",
            "# Desktop application context",
            PromptRewriteScope::Prompt,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-codex-as-role",
            "*as Codex:*",
            "as an assistant:",
            PromptRewriteScope::Prompt,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-codex-intro",
            "*the codex cli is an open*source project*",
            "",
            PromptRewriteScope::Prompt,
            true,
        ),
        PromptRewriteRule::with_scope(
            "preset-anthropic-billing",
            "*x-anthropic-billing-header:*",
            "",
            PromptRewriteScope::Prompt,
            true,
        ),
    ]
}

pub fn unrelated_after() {
    let brace = '}';
}
`;

// Verbatim `recommended_preset_rules()` from Antigravity-Manager beta `src-tauri/src/proxy/config.rs`
const VERBATIM_CONFIG_RS_RECOMMENDED_PRESET_RULES = `impl PromptRewriteConfig {
    /// 官方推荐的内置风控预设规则集（经过生产环境与 WAF 实测验证）
    pub fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
        vec![
            PromptRewriteRule::with_scope(
                "preset-opencode",
                "You are an AI agent running in OpenCode*",
                "",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-claude-code-agent",
                "You are an interactive agent that helps users with software engineering tasks*",
                "",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-opencode-session-move",
                "*tools.opencode.session*move*",
                "tools.opencode.session_relocate",
                PromptRewriteScope::All,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-dsh-identity",
                "You are an AI agent powered by DeepSeek Harness*",
                "",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-dsh-model",
                "You are a coding agent powered by *gemini*",
                "",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-dsh-browser-context",
                "*The browser provides no implicit DOM, route, or screenshot context*",
                "The browser exposes no DOM tree, route list, or page screenshot context",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-workbuddy",
                "*WorkBuddy*",
                "",
                PromptRewriteScope::All,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-workbuddy-powered-by",
                "*This conversation is powered by *",
                "Selected model: ",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-codex-desktop-context",
                "*# Codex desktop context*",
                "# Desktop application context",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-codex-as-role",
                "*as Codex:*",
                "as an assistant:",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-codex-intro",
                "*the codex cli is an open*source project*",
                "",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                "preset-anthropic-billing",
                "*x-anthropic-billing-header:*",
                "",
                PromptRewriteScope::Prompt,
                true,
            ),
        ]
    }
}`;

describe("parseRustPresetRules", () => {
  it("parses exact AGT beta with_scope snippet matching all 12 RECOMMENDED_PRESET_RULES", () => {
    const rules = parseRustPresetRules(REAL_AGT_BETA_CONFIG_SNIPPET);
    assert.equal(rules.length, RECOMMENDED_PRESET_RULES.length);
    assert.deepEqual(rules, RECOMMENDED_PRESET_RULES);
  });

  it("supports struct-literal PromptRewriteRule fallback format with various string conversions", () => {
    const rustSrc = `
    pub fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
        vec![
            PromptRewriteRule {
                id: "struct-rule-1".to_string(),
                pattern: String::from("*tool-hint*"), // trailing comment
                replacement: "clean-hint".into(),
                scope: PromptRewriteScope::Tools,
                enabled: false,
            },
            PromptRewriteRule {
                id: "struct-rule-2".to_owned(),
                pattern: r#"*raw "quoted" pattern*"#.to_string(),
                replacement: r##"replaced #"# text"##.to_string(),
                scope: PromptRewriteScope::All,
                enabled: true,
            },
        ]
    }
    `;

    const rules = parseRustPresetRules(rustSrc);
    assert.deepEqual(rules, [
      {
        id: "struct-rule-1",
        pattern: "*tool-hint*",
        replacement: "clean-hint",
        scope: "tools",
        enabled: false,
      },
      {
        id: "struct-rule-2",
        pattern: '*raw "quoted" pattern*',
        replacement: 'replaced #"# text',
        scope: "all",
        enabled: true,
      },
    ]);
  });

  it("unescapes Rust string escapes and raw strings accurately", () => {
    const rustSrc = String.raw`
    fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
        vec![
            PromptRewriteRule::with_scope(
                "escape-test",
                "*foo\\*bar*",
                "line1\n\t\"quoted\"\r\0\u{1F600}",
                PromptRewriteScope::Prompt,
                true,
            ),
            PromptRewriteRule::with_scope(
                r"raw-plain",
                r"*keep\\backslash*",
                r##"keep "# inside"##,
                PromptRewriteScope::All,
                false,
            ),
        ]
    }
    `;

    const rules = parseRustPresetRules(rustSrc);
    assert.deepEqual(rules, [
      {
        id: "escape-test",
        pattern: "*foo\\*bar*",
        replacement: 'line1\n\t"quoted"\r\0\u{1F600}',
        scope: "prompt",
        enabled: true,
      },
      {
        id: "raw-plain",
        pattern: "*keep\\\\backslash*",
        replacement: 'keep "# inside',
        scope: "all",
        enabled: false,
      },
    ]);
  });

  it("parses verbatim recommended_preset_rules() from real config.rs into 12 rules", () => {
    const rules = parseRustPresetRules(VERBATIM_CONFIG_RS_RECOMMENDED_PRESET_RULES);
    assert.equal(rules.length, 12);
    assert.deepEqual(rules, RECOMMENDED_PRESET_RULES);
  });

  it("supports PromptRewriteRule::new(...) with scope fixed to 'all'", () => {
    const rustSrc = `
    fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
        vec![
            PromptRewriteRule::new("new-rule-1", "*alpha*", "beta", true),
            PromptRewriteRule::new("new-rule-2", "*gamma*", "", false),
        ]
    }
    `;
    const rules = parseRustPresetRules(rustSrc);
    assert.deepEqual(rules, [
      {
        id: "new-rule-1",
        pattern: "*alpha*",
        replacement: "beta",
        scope: "all",
        enabled: true,
      },
      {
        id: "new-rule-2",
        pattern: "*gamma*",
        replacement: "",
        scope: "all",
        enabled: false,
      },
    ]);
  });

  it("defaults omitted struct-literal scope to 'all' and omitted enabled to true", () => {
    const rustSrc = `
    fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
        vec![
            PromptRewriteRule {
                id: "defaulted-struct".to_string(),
                pattern: "*foo*".to_string(),
                replacement: "bar".to_string(),
            },
        ]
    }
    `;
    const rules = parseRustPresetRules(rustSrc);
    assert.deepEqual(rules, [
      {
        id: "defaulted-struct",
        pattern: "*foo*",
        replacement: "bar",
        scope: "all",
        enabled: true,
      },
    ]);
  });

  it("throws when rule count exceeds MAX_RULES instead of silently truncating", () => {
    const items = [];
    for (let idx = 0; idx < MAX_RULES + 1; idx += 1) {
      items.push(
        `PromptRewriteRule::with_scope("rule-${idx}", "pat-${idx}", "", PromptRewriteScope::Prompt, true),`,
      );
    }
    const rustSrc = `fn recommended_preset_rules() -> Vec<PromptRewriteRule> { vec![\n${items.join("\n")}\n] }`;
    assert.throws(
      () => parseRustPresetRules(rustSrc),
      /PromptRewriteRule #65: exceeds maximum of 64 rules/,
    );
  });

  it("throws in strict mode on invalid entries, non-literal args, scope aliases, duplicates, and oversized fields", () => {
    // 1. Constant reference / function call as argument (must report rule # and reason without raw source)
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![
                PromptRewriteRule::with_scope("ok-1", "*a*", "", PromptRewriteScope::All, true),
                PromptRewriteRule::with_scope("bad-2", SECRET_PATTERN_CONST, "", PromptRewriteScope::All, true),
            ]
        }`),
      (err) => {
        assert.match(err.message, /#2/);
        assert.match(err.message, /string literal/i);
        assert.ok(!err.message.includes("SECRET_PATTERN_CONST"));
        return true;
      },
    );

    // 2. Scope written as alias or unqualified variant
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![
                PromptRewriteRule::with_scope("alias-scope", "*a*", "", Scope::Prompt, true),
            ]
        }`),
      /#1.*PromptRewriteScope::All/,
    );
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![
                PromptRewriteRule::with_scope("bare-scope", "*a*", "", Prompt, true),
            ]
        }`),
      /#1.*PromptRewriteScope::All/,
    );

    // 3. Unknown associated function
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![
                PromptRewriteRule::custom_helper("x", "*a*", ""),
            ]
        }`),
      /#1.*associated function/i,
    );

    // 4. Duplicate id
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![
                PromptRewriteRule::new("dup-id", "*a*", "", true),
                PromptRewriteRule::new("dup-id", "*b*", "", true),
            ]
        }`),
      /#2.*duplicate/i,
    );

    // 5. Empty id or empty pattern
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![PromptRewriteRule::new("", "*a*", "", true)]
        }`),
      /#1.*'id' must not be empty/,
    );
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![PromptRewriteRule::new("empty-pat", "", "", true)]
        }`),
      /#1.*'pattern' must not be empty/,
    );

    // 6. Oversized pattern (> 8192) and replacement (> 16384)
    const tooLongPattern = "x".repeat(MAX_PATTERN_CHARS + 1);
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![PromptRewriteRule::new("long-pat", "${tooLongPattern}", "", true)]
        }`),
      /#1.*8192/,
    );
    const tooLongReplacement = "y".repeat(MAX_REPLACEMENT_CHARS + 1);
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![PromptRewriteRule::new("long-rep", "*a*", "${tooLongReplacement}", true)]
        }`),
      /#1.*16384/,
    );
  });

  it("throws when a vec![] element is not a PromptRewriteRule or when function body is not a single vec![]", () => {
    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            vec![
                PromptRewriteRule::with_scope("ok-1", "*a*", "", PromptRewriteScope::All, true),
                make_rule("x"),
            ]
        }`),
      (err) => {
        assert.match(err.message, /#2/);
        assert.ok(!err.message.includes("make_rule"));
        return true;
      },
    );

    assert.throws(
      () =>
        parseRustPresetRules(`
        fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
            let mut v = Vec::new();
            v.push(PromptRewriteRule::with_scope("ok-1", "*a*", "", PromptRewriteScope::All, true));
            v
        }`),
      /vec!\[\.\.\.\]/,
    );
  });

  it("throws descriptive errors on missing function or zero valid rules", () => {
    assert.throws(() => parseRustPresetRules(""), /non-empty string/i);
    assert.throws(() => parseRustPresetRules("fn other() {}"), /recommended_preset_rules/);
    assert.throws(
      () => parseRustPresetRules("fn recommended_preset_rules() -> Vec<PromptRewriteRule> { vec![] }"),
      /No valid PromptRewriteRule/,
    );
  });
});

describe("fetchUpstreamPresetRules", () => {
  it("fetches, parses, and formats upstream preset rules", async () => {
    let seenUrl = "";
    let seenHeaders = null;
    const mockFetch = async (url, init) => {
      seenUrl = url;
      seenHeaders = init?.headers;
      return new Response(REAL_AGT_BETA_CONFIG_SNIPPET, { status: 200 });
    };

    const result = await fetchUpstreamPresetRules({ fetchImpl: mockFetch });
    assert.equal(seenUrl, UPSTREAM_AGT_BETA_CONFIG_URL);
    assert.equal(seenHeaders.Accept, "text/plain");
    assert.equal(seenHeaders["User-Agent"], "magpie-agy2api-plugin");
    assert.equal(result.ok, true);
    assert.equal(result.source, UPSTREAM_AGT_BETA_CONFIG_URL);
    assert.equal(result.branch, "beta");
    assert.ok(!Number.isNaN(Date.parse(result.fetchedAt)));
    assert.equal(result.count, 12);
    assert.deepEqual(result.rules, RECOMMENDED_PRESET_RULES);
  });

  it("throws on non-OK HTTP responses and request timeouts", async () => {
    await assert.rejects(
      () =>
        fetchUpstreamPresetRules({
          fetchImpl: async () => new Response("Not Found", { status: 404, statusText: "Not Found" }),
        }),
      /Upstream HTTP 404/,
    );

    await assert.rejects(
      () =>
        fetchUpstreamPresetRules({
          timeoutMs: 25,
          fetchImpl: (_url, init) =>
            new Promise((_resolve, reject) => {
              init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
            }),
        }),
      /timed out/i,
    );
  });

  it("rejects upstream responses exceeding 2 MiB", async () => {
    const oversized = "a".repeat(MAX_UPSTREAM_BODY_BYTES + 1);
    await assert.rejects(
      () =>
        fetchUpstreamPresetRules({
          fetchImpl: async () => new Response(oversized, { status: 200 }),
        }),
      /exceeds maximum size/i,
    );

    await assert.rejects(
      () =>
        fetchUpstreamPresetRules({
          fetchImpl: async () =>
            new Response("small", {
              status: 200,
              headers: { "Content-Length": String(MAX_UPSTREAM_BODY_BYTES + 1) },
            }),
        }),
      /exceeds maximum size/i,
    );
  });
});

describe("startPageService & plugin wiring", () => {
  const cleanups = [];

  after(async () => {
    while (cleanups.length > 0) {
      const fn = cleanups.pop();
      await fn();
    }
  });

  it("serves health, rewritten HTML with strict CSP, static assets, upstream-presets API, 404, and reuses active port", async () => {
    const port = await allocateFreePort();
    let failUpstream = true;
    const mockFetch = async () => {
      if (failUpstream) {
        return new Response("upstream down", { status: 503, statusText: "Service Unavailable" });
      }
      return new Response(REAL_AGT_BETA_CONFIG_SNIPPET, { status: 200 });
    };

    const svc = await startPageService({
      port,
      fetchImpl: mockFetch,
    });
    cleanups.push(() => svc.close());

    assert.equal(svc.ok, true);
    assert.equal(svc.port, port);

    const registry = globalThis[Symbol.for("magpie.agy2api.pageServices")];
    assert.ok(registry instanceof Map);
    assert.equal(registry.get(port)?.server, svc.server);

    // Reload / duplicate start on same port reuses cleanly without EADDRINUSE
    const reused = await startPageService({ port, fetchImpl: mockFetch });
    assert.equal(reused.server, svc.server);

    const base = `http://127.0.0.1:${port}`;

    // 1. GET /health
    const healthRes = await fetch(`${base}/health`);
    assert.equal(healthRes.status, 200);
    assert.equal(healthRes.headers.get("x-content-type-options"), "nosniff");
    assert.equal(healthRes.headers.get("referrer-policy"), "no-referrer");
    assert.equal(healthRes.headers.get("cache-control"), "no-store");
    assert.deepEqual(await healthRes.json(), { ok: true, port });

    // 2. GET / (and /index.html, /sanitizer-panel.html)
    const expectedCsp = `default-src 'none'; script-src 'self' ${base}; style-src 'self' ${base} 'unsafe-inline'; connect-src 'self' ${base}; img-src 'self' ${base} data:; font-src 'self' ${base}`;
    assert.equal(buildHtmlCsp(port), expectedCsp);
    assert.equal(expectedCsp.includes("frame-ancestors"), false);
    for (const htmlPath of ["/", "/index.html", "/sanitizer-panel.html"]) {
      const htmlRes = await fetch(`${base}${htmlPath}`);
      assert.equal(htmlRes.status, 200);
      assert.match(htmlRes.headers.get("content-type") || "", /^text\/html/);
      assert.equal(htmlRes.headers.get("content-security-policy"), expectedCsp);
      const htmlText = await htmlRes.text();
      assert.ok(htmlText.includes('<script src="service-bridge.js"></script>'));
      assert.ok(!htmlText.includes("_magpie/bridge.js"));
    }

    // 3. Static assets
    const cssRes = await fetch(`${base}/sanitizer-panel.css`);
    assert.equal(cssRes.status, 200);
    assert.match(cssRes.headers.get("content-type") || "", /^text\/css/);
    await cssRes.text();

    const jsRes = await fetch(`${base}/sanitizer-panel.js`);
    assert.equal(jsRes.status, 200);
    assert.match(jsRes.headers.get("content-type") || "", /^text\/javascript/);
    await jsRes.text();

    const svgRes = await fetch(`${base}/icon.svg`);
    assert.equal(svgRes.status, 200);
    assert.equal(svgRes.headers.get("content-type"), "image/svg+xml");
    await svgRes.text();

    // 4. OPTIONS & method restriction (GET only; POST/PUT return 405)
    const optRes = await fetch(`${base}/api/upstream-presets`, { method: "OPTIONS" });
    assert.equal(optRes.status, 204);
    assert.equal(optRes.headers.get("access-control-allow-origin"), "*");
    for (const method of ["POST", "PUT", "DELETE"]) {
      const methodRes = await fetch(`${base}/api/upstream-presets`, { method });
      assert.equal(methodRes.status, 405);
      assert.deepEqual(await methodRes.json(), { ok: false, error: "Method not allowed" });
    }

    // 5. Upstream failure -> 502 JSON (and not cached)
    const errRes = await fetch(`${base}/api/upstream-presets`);
    assert.equal(errRes.status, 502);
    const errJson = await errRes.json();
    assert.equal(errJson.ok, false);
    assert.match(errJson.error, /503/);

    // 6. GET /api/upstream-presets success + CORS headers for sandboxed Origin: null iframe
    failUpstream = false;
    const apiRes = await fetch(`${base}/api/upstream-presets`, { method: "GET" });
    assert.equal(apiRes.status, 200);
    assert.equal(apiRes.headers.get("access-control-allow-origin"), "*");
    const data = await apiRes.json();
    assert.equal(data.ok, true);
    assert.equal(data.branch, "beta");
    assert.equal(data.count, 12);
    assert.deepEqual(data.rules, RECOMMENDED_PRESET_RULES);

    // 7. Unknown path -> 404
    const notFoundRes = await fetch(`${base}/does-not-exist`);
    assert.equal(notFoundRes.status, 404);
    assert.deepEqual(await notFoundRes.json(), { ok: false, error: "Not found" });

    await svc.close();
    assert.equal(registry.has(port), false);
  });

  it("caches upstream successes, coalesces concurrent requests, and does not cache failures", async () => {
    const port = await allocateFreePort();
    let fetchCalls = 0;
    let mode = "fail";
    let releaseGate;

    const svc = await startPageService({
      port,
      cacheTtlMs: 40,
      fetchImpl: async () => {
        fetchCalls += 1;
        if (mode === "fail") {
          return new Response("bad gateway", { status: 502, statusText: "Bad Gateway" });
        }
        if (mode === "slow") {
          await new Promise((resolve) => {
            releaseGate = resolve;
          });
        }
        return new Response(REAL_AGT_BETA_CONFIG_SNIPPET, { status: 200 });
      },
    });
    cleanups.push(() => svc.close());

    const base = `http://127.0.0.1:${port}`;

    // Failure is not cached
    const fail1 = await fetch(`${base}/api/upstream-presets`);
    assert.equal(fail1.status, 502);
    await fail1.json();
    const fail2 = await fetch(`${base}/api/upstream-presets`);
    assert.equal(fail2.status, 502);
    await fail2.json();
    assert.equal(fetchCalls, 2);

    // Concurrent GET requests coalesce into a single in-flight upstream fetch
    mode = "slow";
    const p1 = fetch(`${base}/api/upstream-presets`);
    const p2 = fetch(`${base}/api/upstream-presets`);
    const p3 = fetch(`${base}/api/upstream-presets`);
    await new Promise((resolve) => setTimeout(resolve, 15));
    assert.equal(fetchCalls, 3);
    releaseGate();

    const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
    assert.equal(r1.status, 200);
    assert.equal(r2.status, 200);
    assert.equal(r3.status, 200);
    await Promise.all([r1.json(), r2.json(), r3.json()]);
    assert.equal(fetchCalls, 3);

    // Subsequent GET within TTL uses cached result without upstream fetch
    mode = "ok";
    const cachedRes = await fetch(`${base}/api/upstream-presets`);
    assert.equal(cachedRes.status, 200);
    await cachedRes.json();
    assert.equal(fetchCalls, 3);

    // After TTL expires, next GET fetches again
    await new Promise((resolve) => setTimeout(resolve, 60));
    const refreshedRes = await fetch(`${base}/api/upstream-presets`);
    assert.equal(refreshedRes.status, 200);
    await refreshedRes.json();
    assert.equal(fetchCalls, 4);

    await svc.close();
  });

  it("closes old port on port change, replaces handler on same-port restart, and stops via stopPageService", async () => {
    const port1 = await allocateFreePort();
    const port2 = await allocateFreePort();
    const registry = globalThis[Symbol.for("magpie.agy2api.pageServices")];

    const svc1 = await startPageService({
      port: port1,
      fetchImpl: async () => new Response(REAL_AGT_BETA_CONFIG_SNIPPET, { status: 200 }),
    });
    cleanups.push(() => stopPageService());
    assert.equal(svc1.ok, true);
    assert.equal(svc1.server.listening, true);

    // Switching to port2 closes port1 after port2 starts
    const svc2 = await startPageService({
      port: port2,
      fetchImpl: async () => new Response(REAL_AGT_BETA_CONFIG_SNIPPET, { status: 200 }),
    });
    assert.equal(svc2.ok, true);
    assert.equal(svc2.server.listening, true);
    assert.equal(svc1.server.listening, false);
    assert.equal(registry.has(port1), false);
    assert.equal(registry.has(port2), true);
    await assert.rejects(() => fetch(`http://127.0.0.1:${port1}/health`));

    // Restarting on same port2 reuses server but applies new request handler
    const svc2Reloaded = await startPageService({
      port: port2,
      fetchImpl: async () =>
        new Response(
          `fn recommended_preset_rules() -> Vec<PromptRewriteRule> {
              vec![PromptRewriteRule::new("reloaded-rule", "*reloaded*", "", true)]
          }`,
          { status: 200 },
        ),
    });
    assert.equal(svc2Reloaded.server, svc2.server);
    const reloadedRes = await fetch(`http://127.0.0.1:${port2}/api/upstream-presets`);
    assert.equal(reloadedRes.status, 200);
    const reloadedData = await reloadedRes.json();
    assert.equal(reloadedData.count, 1);
    assert.equal(reloadedData.rules[0].id, "reloaded-rule");

    // stopPageService stops the active service
    await stopPageService();
    assert.equal(svc2.server.listening, false);
    assert.equal(registry.size, 0);
    await assert.rejects(() => fetch(`http://127.0.0.1:${port2}/health`));
  });

  it("handles EADDRINUSE gracefully without crashing when port is occupied externally", async () => {
    const port = await allocateFreePort();
    const blocker = net.createServer();
    await new Promise((resolve) => blocker.listen(port, "127.0.0.1", resolve));
    cleanups.push(() => new Promise((resolve) => blocker.close(() => resolve())));

    const res = await startPageService({ port });
    assert.equal(res.ok, false);
    assert.equal(res.port, port);
    assert.ok(res.error);
  });

  it("wires package.json magpie.page.service/options and index.mjs disablePageService option", async () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(PLUGIN_ROOT, "package.json"), "utf8"));
    assert.deepEqual(pkg.magpie?.page?.service, {
      port: DEFAULT_PAGE_SERVICE_PORT,
      option: "pageServicePort",
    });
    assert.equal(pkg.magpie?.options?.pageServicePort, DEFAULT_PAGE_SERVICE_PORT);

    const port = await allocateFreePort();
    cleanups.push(() => stopPageService());
    await plugin.server({}, { pageServicePort: port });
    const registry = globalThis[Symbol.for("magpie.agy2api.pageServices")];
    // First listen attempt is awaited so desktop `pageHost` gets a live port immediately
    assert.equal(registry.get(port)?.server?.listening, true);

    const hooks = await plugin.server({}, { disablePageService: true });
    assert.equal(hooks.provider.id, "agy2api");
    assert.equal(registry.size, 0);
  });

  it("keeps trying to start when the previous plugin host still holds the port, and stops trying once disabled", async () => {
    const registry = globalThis[Symbol.for("magpie.agy2api.pageServices")];
    const health = async (port) => {
      try {
        const res = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(500) });
        return res.status === 200 ? (await res.json()).ok : false;
      } catch {
        return false;
      }
    };
    const waitFor = async (check, ms) => {
      const deadline = Date.now() + ms;
      while (Date.now() < deadline) {
        if (await check()) return true;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      return false;
    };

    // 1. The old host is still listening when the reloaded plugin starts
    const port = await allocateFreePort();
    const oldHost = net.createServer((socket) => socket.destroy());
    await new Promise((resolve) => oldHost.listen(port, "127.0.0.1", resolve));
    cleanups.push(() => stopPageService());
    await plugin.server({}, { pageServicePort: port });
    await new Promise((resolve) => setTimeout(resolve, 120));
    assert.equal(registry.get(port)?.server?.listening ?? false, false);

    // It exits a moment later: the page service comes up on its own
    await new Promise((resolve) => oldHost.close(() => resolve()));
    assert.equal(await waitFor(() => health(port), 4000), true);

    // 2. Disabling the service while a start is still being retried ends the retries
    const port2 = await allocateFreePort();
    const blocker = net.createServer((socket) => socket.destroy());
    await new Promise((resolve) => blocker.listen(port2, "127.0.0.1", resolve));
    await plugin.server({}, { pageServicePort: port2 });
    await new Promise((resolve) => setTimeout(resolve, 120));
    await plugin.server({}, { disablePageService: true });
    await new Promise((resolve) => blocker.close(() => resolve()));
    assert.equal(await waitFor(() => health(port2), 1500), false);
    assert.equal(registry.size, 0);
  });

  it("sanitizer-panel.js onSync wakes dormant service on non-JSON 502 or network error, polls health, retries, and skips retry on JSON 502", async () => {
    const jsSource = fs.readFileSync(path.join(PLUGIN_ROOT, "ui/sanitizer-panel.js"), "utf8");

    function createPanelHarness(fetchMock) {
      const elements = new Map();
      const makeEl = (id) => {
        const listeners = {};
        const el = {
          id,
          textContent: "",
          innerHTML: "",
          value: "",
          checked: false,
          disabled: false,
          hidden: false,
          dataset: {},
          className: "",
          style: {},
          attributes: {},
          children: [],
          classList: {
            add() {},
            remove() {},
            toggle() {},
            contains() { return false; },
          },
          setAttribute(k, v) { this.attributes[k] = String(v); },
          getAttribute(k) { return this.attributes[k]; },
          addEventListener(type, fn) {
            listeners[type] = listeners[type] || [];
            listeners[type].push(fn);
          },
          dispatch(type) {
            for (const fn of listeners[type] || []) fn({ target: el, preventDefault() {} });
          },
          appendChild(child) {
            if (child && typeof child === "object") child.parentNode = el;
            this.children.push(child);
            return child;
          },
          removeChild(child) {
            const idx = this.children.indexOf(child);
            if (idx >= 0) this.children.splice(idx, 1);
            return child;
          },
          get firstChild() { return this.children[0] || null; },
          get lastChild() { return this.children[this.children.length - 1] || null; },
          querySelector() { return null; },
          querySelectorAll() { return []; },
          focus() {},
        };
        return el;
      };
      for (const id of [
        "app", "status", "btn-save", "btn-revert", "btn-reset", "btn-sync-upstream", "btn-add",
        "opt-enabled", "opt-rules-enabled", "opt-norm-id", "opt-tools", "opt-sideload",
        "rules-list", "rules-summary", "rules-toggle", "rules-chevron", "rules-body",
        "banner-err", "banner-text", "btn-retry", "foot-hint", "empty-rules",
      ]) {
        elements.set(id, makeEl(id));
      }

      const listeners = {};
      const documentMock = {
        documentElement: { lang: "en", setAttribute() {} },
        title: "",
        getElementById(id) {
          if (!elements.has(id)) elements.set(id, makeEl(id));
          return elements.get(id);
        },
        createElement(tag) { return makeEl(tag); },
        createElementNS(_ns, tag) { return makeEl(tag); },
        createDocumentFragment() { return makeEl("fragment"); },
        createTextNode(text) { return { nodeType: 3, textContent: String(text || "") }; },
        querySelectorAll() { return []; },
        addEventListener(type, fn) {
          listeners[type] = listeners[type] || [];
          listeners[type].push(fn);
        },
      };
      const windowMock = {
        __magpieServiceHosted: true,
        magpie: {
          ready: Promise.resolve({ lang: "en" }),
          options: {
            get: async () => ({
              promptSanitizer: true,
              promptRewrite: {
                enabled: true,
                normalize_identity: true,
                sideload_mode: "off",
                sanitize_tools_description: true,
                rules: [{ id: "r1", pattern: "foo", replacement: "bar", scope: "all", enabled: true }],
              },
            }),
          },
        },
        location: { search: "", href: "http://127.0.0.1:18417/", replace() {} },
        parent: {
          postMessage(msg) {
            if (msg?.method === "magpie.options.get") {
              setTimeout(() => {
                for (const fn of listeners.message || []) {
                  fn({
                    source: windowMock.parent,
                    data: {
                      type: "magpie-page-rpc-response",
                      id: msg.id,
                      result: {
                        promptSanitizer: true,
                        promptRewrite: {
                          enabled: true,
                          normalize_identity: true,
                          sideload_mode: "off",
                          sanitize_tools_description: true,
                          rules: [{ id: "r1", pattern: "foo", replacement: "bar", scope: "all", enabled: true }],
                        },
                      },
                    },
                  });
                }
              }, 0);
            }
          },
        },
        addEventListener(type, fn) {
          listeners[type] = listeners[type] || [];
          listeners[type].push(fn);
        },
      };
      windowMock.window = windowMock;

      const sandbox = {
        window: windowMock,
        document: documentMock,
        navigator: { language: "en-US" },
        URLSearchParams,
        fetch: async (url, init) => {
          // The panel loads api/aux-routing/state on init; answer it here so the
          // upstream-preset wake/retry call-order assertions below stay exact.
          if (String(url).startsWith("api/aux-routing/state")) {
            return new Response(
              JSON.stringify({ ok: true, preserveCacheEffort: true, preserveSource: "default", catalogStatus: "ok", catalogError: "", models: [] }),
              { status: 200, headers: { "content-type": "application/json" } },
            );
          }
          return fetchMock(url, init);
        },
        setTimeout,
        clearTimeout,
        Date,
        Promise,
        Error,
        Math,
        Object,
        Array,
        String,
        Boolean,
        Number,
        JSON,
        RegExp,
      };
      vm.runInNewContext(jsSource, sandbox);
      for (const fn of listeners.DOMContentLoaded || []) fn();
      return { elements, sandbox };
    }

    // Case 1: Non-JSON proxy 502 -> wakes "./", polls health until {ok:true}, retries api/upstream-presets while keeping syncing=true
    const calls1 = [];
    let presetAttempt = 0;
    let healthAttempt = 0;
    let syncingDuringWake = null;
    const h1 = createPanelHarness(async (url) => {
      const u = String(url);
      calls1.push(u);
      if (u === "api/upstream-presets") {
        presetAttempt++;
        if (presetAttempt === 1) {
          return new Response("502 Bad Gateway (dormant)", {
            status: 502,
            headers: { "content-type": "text/plain" },
          });
        }
        return new Response(
          JSON.stringify({
            ok: true,
            rules: [{ id: "upstream-1", pattern: "abc", replacement: "xyz", scope: "all", enabled: true }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (u === "./") {
        syncingDuringWake = h1.elements.get("btn-sync-upstream").getAttribute("aria-busy");
        return new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } });
      }
      if (u === "health") {
        healthAttempt++;
        if (healthAttempt === 1) {
          return new Response("starting", { status: 502 });
        }
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected ${u}`);
    });
    await new Promise((r) => setTimeout(r, 25));
    const syncBtn1 = h1.elements.get("btn-sync-upstream");
    syncBtn1.dispatch("click"); // arm confirmation
    syncBtn1.dispatch("click"); // execute sync
    await new Promise((r) => setTimeout(r, 400));

    assert.equal(syncingDuringWake, "true");
    assert.equal(syncBtn1.getAttribute("aria-busy"), "false");
    assert.deepEqual(calls1, ["api/upstream-presets", "./", "health", "health", "api/upstream-presets"]);
    assert.equal(h1.elements.get("status").className.includes("ok"), true);

    // Case 2: JSON 502 { ok: false, error: "upstream github 503" } MUST NOT wake or retry
    const calls2 = [];
    const h2 = createPanelHarness(async (url) => {
      const u = String(url);
      calls2.push(u);
      if (u === "api/upstream-presets") {
        return new Response(JSON.stringify({ ok: false, error: "upstream github 503" }), {
          status: 502,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Should not call ${u}`);
    });
    await new Promise((r) => setTimeout(r, 25));
    const syncBtn2 = h2.elements.get("btn-sync-upstream");
    syncBtn2.dispatch("click");
    syncBtn2.dispatch("click");
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(calls2, ["api/upstream-presets"]);
    assert.match(h2.elements.get("status").textContent, /upstream github 503/);

    // Case 3: Fetch reject (network error while host asleep) also wakes "./", polls health, and retries
    const calls3 = [];
    let p3 = 0;
    const h3 = createPanelHarness(async (url) => {
      const u = String(url);
      calls3.push(u);
      if (u === "api/upstream-presets") {
        p3++;
        if (p3 === 1) throw new TypeError("Failed to fetch");
        return new Response(
          JSON.stringify({
            ok: true,
            rules: [{ id: "net-1", pattern: "foo", replacement: "bar", scope: "all", enabled: true }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (u === "./") return new Response("<html></html>", { status: 200 });
      if (u === "health") {
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected ${u}`);
    });
    await new Promise((r) => setTimeout(r, 25));
    const syncBtn3 = h3.elements.get("btn-sync-upstream");
    syncBtn3.dispatch("click");
    syncBtn3.dispatch("click");
    await new Promise((r) => setTimeout(r, 80));
    assert.deepEqual(calls3, ["api/upstream-presets", "./", "health", "api/upstream-presets"]);
    assert.equal(h3.elements.get("status").className.includes("ok"), true);
  });

  it("exposes GET /api/aux-routing/diagnostics with CORS headers and rejects non-GET methods", async () => {
    const { clearAuxRoutingDiagnostics, handleGatewayOnRequest } = await import("../lib/aux-router.mjs");
    clearAuxRoutingDiagnostics();

    await handleGatewayOnRequest(
      {
        model: "claude-opus-5-5",
        max_tokens: 2048,
        metadata: { purpose: "project_memory_extract" },
        output_config: { effort: "high" },
        messages: [{ role: "user", content: "PRIVATE_PROMPT_NEVER_LOG" }],
      },
      {
        protocol: "anthropic",
        session: "diag-test-sess-1",
        path: "/v1/messages",
        options: { auxIncompatiblePolicy: "current_low" },
      },
    );

    const port = await allocateFreePort();
    const svc = await startPageService({ port });
    assert.equal(svc.ok, true);
    try {
      const res = await fetch(`${svc.url}/api/aux-routing/diagnostics`);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("access-control-allow-origin"), "*");
      const data = await res.json();
      assert.equal(data.ok, true);
      assert.equal(Array.isArray(data.records), true);
      assert.equal(data.records.length, 1);
      assert.equal(data.records[0].detector, "explicit_purpose");
      assert.equal(data.records[0].policy, "current_low");
      assert.equal(JSON.stringify(data).includes("PRIVATE_PROMPT_NEVER_LOG"), false);
      assert.equal(JSON.stringify(data).includes("diag-test-sess-1"), false);

      const postRes = await fetch(`${svc.url}/api/aux-routing/diagnostics`, { method: "POST" });
      assert.equal(postRes.status, 405);
    } finally {
      await svc.close();
      clearAuxRoutingDiagnostics();
    }
  });

  it("exposes GET /api/aux-routing/state with model effectiveEfforts, ?refresh=1, empty/error/ambiguous states, and master switch sources", async () => {
    const { clearAuxRouterState, setPluginRuntimeContext } = await import("../lib/aux-router.mjs");
    const { clearModelCache } = await import("../lib/models.mjs");

    const resetRuntime = () => {
      clearAuxRouterState();
      clearModelCache();
      setPluginRuntimeContext({ directory: "", magpie: null, staticOptions: null, authScope: null });
    };

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agy2api-aux-state-"));
    resetRuntime();

    let catalogMode = "initial";
    let catalogFetchCalls = 0;
    const catalogFetchImpl = async (url) => {
      const u = String(url);
      if (u.endsWith("/api/models")) {
        catalogFetchCalls += 1;
        if (catalogMode === "error") {
          return new Response("upstream error", { status: 500 });
        }
        if (catalogMode === "empty") {
          return new Response(JSON.stringify({ models: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        const models = [
          {
            id: "gemini-3.8-flash",
            name: "Gemini 3.8 Flash",
            provider: "MODEL_PROVIDER_GOOGLE",
            thinking_levels: ["low", "medium", "high"],
            capabilities: { thinking: true },
          },
          {
            id: "gpt-oss-120b",
            name: "GPT OSS 120B",
            provider: "MODEL_PROVIDER_OPENAI",
            thinking_levels: ["medium"],
            capabilities: { thinking: true },
          },
          {
            id: "claude-sonnet-5-5",
            name: "Claude Sonnet 5.5",
            provider: "MODEL_PROVIDER_ANTHROPIC",
            capabilities: { thinking: true },
          },
          {
            id: "gemini-2.5-flash-lite",
            name: "Gemini 2.5 Flash Lite",
            provider: "MODEL_PROVIDER_GOOGLE",
            capabilities: { thinking: false },
          },
          {
            id: "opus-high-alias",
            name: "Opus High Alias",
            provider: "MODEL_PROVIDER_ANTHROPIC",
            alias: true,
            alias_target: "claude-opus-5-5-high",
          },
          {
            id: "imagen-4",
            name: "Imagen 4",
            provider: "MODEL_PROVIDER_GOOGLE",
            capabilities: { image_generation: true },
          },
        ];
        if (catalogMode === "refreshed") {
          models.push({
            id: "gemini-4-pro",
            name: "Gemini 4 Pro",
            provider: "MODEL_PROVIDER_GOOGLE",
            thinking_levels: ["low", "high", "xhigh"],
            capabilities: { thinking: true },
          });
        }
        return new Response(JSON.stringify({ models }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (u.endsWith("/api/settings")) {
        return new Response(JSON.stringify({}), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    };

    const port = await allocateFreePort();
    const authScope = { baseUrl: "http://127.0.0.1:8017", apiKey: "sk-state-test" };
    const svc = await startPageService({
      port,
      authScope,
      catalogFetchImpl,
    });

    try {
      // 1. Method restrictions & CORS
      const postRes = await fetch(`${svc.url}/api/aux-routing/state`, { method: "POST" });
      assert.equal(postRes.status, 405);
      assert.equal(postRes.headers.get("access-control-allow-origin"), "*");
      assert.deepEqual(await postRes.json(), { ok: false, error: "Method not allowed" });

      // 2. Normal catalog + default master switch + effectiveEfforts / defaultEffort rules
      const res1 = await fetch(`${svc.url}/api/aux-routing/state`);
      assert.equal(res1.status, 200);
      assert.equal(res1.headers.get("access-control-allow-origin"), "*");
      const data1 = await res1.json();
      assert.equal(data1.ok, true);
      assert.equal(data1.preserveCacheEffort, true);
      assert.equal(data1.preserveSource, "default");
      assert.equal(data1.catalogStatus, "ok");
      assert.equal(data1.catalogError, "");
      assert.equal(catalogFetchCalls, 1);

      const byId = new Map(data1.models.map((m) => [m.id, m]));
      assert.equal(byId.has("imagen-4"), false, "image models must be excluded");
      assert.equal(byId.has("gemini-3.8-flash-low"), false, "synthetic effort suffixes must be excluded");
      assert.equal(byId.has("gemini-3.8-flash-high"), false, "synthetic effort suffixes must be excluded");

      assert.deepEqual(byId.get("gemini-3.8-flash"), {
        id: "gemini-3.8-flash",
        name: "Gemini 3.8 Flash",
        thinkingLevels: ["low", "medium", "high"],
        effectiveEfforts: ["low", "medium", "high"],
        defaultEffort: "low",
        supportsReasoning: true,
        isAliasFixed: false,
        fixedEffort: "",
      });
      assert.deepEqual(byId.get("gpt-oss-120b"), {
        id: "gpt-oss-120b",
        name: "GPT OSS 120B",
        thinkingLevels: ["medium"],
        effectiveEfforts: ["medium"],
        defaultEffort: "medium",
        supportsReasoning: true,
        isAliasFixed: false,
        fixedEffort: "",
      });
      assert.deepEqual(byId.get("claude-sonnet-5-5"), {
        id: "claude-sonnet-5-5",
        name: "Claude Sonnet 5.5",
        thinkingLevels: [],
        effectiveEfforts: ["minimal", "low", "medium", "high"],
        defaultEffort: "low",
        supportsReasoning: true,
        isAliasFixed: false,
        fixedEffort: "",
      });
      assert.deepEqual(byId.get("gemini-2.5-flash-lite"), {
        id: "gemini-2.5-flash-lite",
        name: "Gemini 2.5 Flash Lite",
        thinkingLevels: [],
        effectiveEfforts: [],
        defaultEffort: "",
        supportsReasoning: false,
        isAliasFixed: false,
        fixedEffort: "",
      });
      assert.deepEqual(byId.get("opus-high-alias"), {
        id: "opus-high-alias",
        name: "Opus High Alias",
        thinkingLevels: [],
        effectiveEfforts: ["high"],
        defaultEffort: "high",
        supportsReasoning: true,
        isAliasFixed: true,
        fixedEffort: "high",
      });

      // 3. Cached read without ?refresh=1 does not re-fetch; ?refresh=1 forces re-fetch
      catalogMode = "refreshed";
      const resCached = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataCached = await resCached.json();
      assert.equal(catalogFetchCalls, 1);
      assert.equal(dataCached.models.some((m) => m.id === "gemini-4-pro"), false);

      const resRefreshed = await fetch(`${svc.url}/api/aux-routing/state?refresh=1`);
      const dataRefreshed = await resRefreshed.json();
      assert.equal(catalogFetchCalls, 2);
      assert.equal(dataRefreshed.catalogStatus, "ok");
      assert.equal(dataRefreshed.models.some((m) => m.id === "gemini-4-pro"), true);

      // 3b. Explicit ?refresh=1 when upstream fails MUST report catalogStatus: "error" (never mask failure with stale cache)
      catalogMode = "error";
      const resRefreshFail = await fetch(`${svc.url}/api/aux-routing/state?refresh=1`);
      const dataRefreshFail = await resRefreshFail.json();
      assert.equal(dataRefreshFail.catalogStatus, "error");
      assert.deepEqual(dataRefreshFail.models, []);

      // 4. Empty catalog -> catalogStatus: "empty"
      clearModelCache();
      catalogMode = "empty";
      const resEmpty = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataEmpty = await resEmpty.json();
      assert.equal(dataEmpty.ok, true);
      assert.equal(dataEmpty.catalogStatus, "empty");
      assert.deepEqual(dataEmpty.models, []);

      // 5. Uncached fetch failure -> catalogStatus: "error"
      clearModelCache();
      catalogMode = "error";
      const resErr = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataErr = await resErr.json();
      assert.equal(dataErr.ok, true);
      assert.equal(dataErr.catalogStatus, "error");
      assert.ok(dataErr.catalogError.length > 0);
      assert.deepEqual(dataErr.models, []);

      // 6. Master switch source checks: plugins.json, settings.json (provider_ui), magpie.options, staticOptions
      clearModelCache();
      catalogMode = "empty";
      fs.writeFileSync(
        path.join(tmpDir, "plugins.json"),
        JSON.stringify({
          plugins: [{ spec: "magpie-agy2api-plugin", options: { preserveCacheEffort: false } }],
        }),
      );
      setPluginRuntimeContext({
        directory: tmpDir,
        magpie: { options: async () => ({ preserve_cache_effort: true }) },
      });
      const resPlugins = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataPlugins = await resPlugins.json();
      assert.equal(dataPlugins.preserveCacheEffort, false);
      assert.equal(dataPlugins.preserveSource, "plugins_json");

      // settings.json without explicit preserve_cache_effort must NOT let magpie.options mask plugins.json
      fs.writeFileSync(path.join(tmpDir, "settings.json"), JSON.stringify({ pluginOptions: {} }));
      const resSettingsEmpty = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataSettingsEmpty = await resSettingsEmpty.json();
      assert.equal(dataSettingsEmpty.preserveCacheEffort, false);
      assert.equal(dataSettingsEmpty.preserveSource, "plugins_json");

      // settings.json with explicit pluginOptions.agy2api.preserve_cache_effort: true -> provider_ui overrides plugins.json
      fs.writeFileSync(
        path.join(tmpDir, "settings.json"),
        JSON.stringify({ pluginOptions: { agy2api: { preserve_cache_effort: true } } }),
      );
      const resProviderUi = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataProviderUi = await resProviderUi.json();
      assert.equal(dataProviderUi.preserveCacheEffort, true);
      assert.equal(dataProviderUi.preserveSource, "provider_ui");

      // Without settings.json or plugins.json: magpie.options("agy2api") -> provider_ui; staticOptions -> plugins_json
      clearAuxRouterState();
      fs.rmSync(path.join(tmpDir, "settings.json"), { force: true });
      fs.rmSync(path.join(tmpDir, "plugins.json"), { force: true });
      setPluginRuntimeContext({
        directory: tmpDir,
        magpie: { options: async () => ({ preserve_cache_effort: false }) },
        staticOptions: { preserveCacheEffort: true },
      });
      const resMagpieUi = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataMagpieUi = await resMagpieUi.json();
      assert.equal(dataMagpieUi.preserveCacheEffort, false);
      assert.equal(dataMagpieUi.preserveSource, "provider_ui");

      setPluginRuntimeContext({
        directory: tmpDir,
        magpie: null,
        staticOptions: { preserveCacheEffort: false },
      });
      const resStatic = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataStatic = await resStatic.json();
      assert.equal(dataStatic.preserveCacheEffort, false);
      assert.equal(dataStatic.preserveSource, "plugins_json");

      // 7. Ambiguous auth scope (both explicit null and multi-login plugin-auth.json) never probes upstream
      const callsBeforeAmbiguous = catalogFetchCalls;
      await startPageService({ port, authScope: null, catalogFetchImpl });
      const resAmbig1 = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataAmbig1 = await resAmbig1.json();
      assert.equal(dataAmbig1.ok, true);
      assert.equal(dataAmbig1.catalogStatus, "auth_scope_ambiguous");
      assert.equal(dataAmbig1.catalogError, "");
      assert.deepEqual(dataAmbig1.models, []);
      assert.equal(catalogFetchCalls, callsBeforeAmbiguous);

      // Multi-login plugin-auth.json via getRegisteredAuthScope()
      fs.writeFileSync(
        path.join(tmpDir, "plugin-auth.json"),
        JSON.stringify({
          "agy2api#a": { key: "sk-a", baseUrl: "http://127.0.0.1:8017" },
          "agy2api#b": { key: "sk-b", baseUrl: "http://127.0.0.1:8018" },
        }),
      );
      setPluginRuntimeContext({ directory: tmpDir, magpie: null, staticOptions: null });
      await startPageService({ port, catalogFetchImpl });
      const resAmbig2 = await fetch(`${svc.url}/api/aux-routing/state`);
      const dataAmbig2 = await resAmbig2.json();
      assert.equal(dataAmbig2.ok, true);
      assert.equal(dataAmbig2.catalogStatus, "auth_scope_ambiguous");
      assert.deepEqual(dataAmbig2.models, []);
      assert.equal(catalogFetchCalls, callsBeforeAmbiguous);
    } finally {
      await svc.close();
      resetRuntime();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  /* ------------------------------------------------------------------ *
   * Auxiliary request routing section of ui/sanitizer-panel.{html,js}
   * Zero-dependency lightweight DOM parser + VM harness (runs everywhere).
   * ------------------------------------------------------------------ */
  const VOID_TAGS = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);

  function createMiniDom(htmlSource) {
    const byId = new Map();
    class MiniEvent {
      constructor(type, init = {}) {
        this.type = String(type);
        this.bubbles = Boolean(init.bubbles);
        this.target = null;
        this.defaultPrevented = false;
      }
      preventDefault() {
        this.defaultPrevented = true;
      }
    }

    function makeNode(tag) {
      const listeners = {};
      const classes = new Set();
      let explicitValue;
      const node = {
        nodeType: tag === "#text" ? 3 : tag === "#fragment" ? 11 : 1,
        tagName: String(tag).toUpperCase(),
        id: "",
        title: "",
        placeholder: "",
        disabled: false,
        hidden: false,
        selected: false,
        tabIndex: 0,
        type: "",
        style: {},
        attributes: {},
        children: [],
        parentNode: null,
        _text: "",
        get className() {
          return Array.from(classes).join(" ");
        },
        set className(v) {
          classes.clear();
          String(v || "").split(/\s+/).filter(Boolean).forEach((c) => classes.add(c));
        },
        classList: {
          add(...cs) { cs.filter(Boolean).forEach((c) => classes.add(c)); },
          remove(...cs) { cs.forEach((c) => classes.delete(c)); },
          toggle(c, force) {
            const on = force === undefined ? !classes.has(c) : Boolean(force);
            if (on) classes.add(c);
            else classes.delete(c);
            return on;
          },
          contains(c) { return classes.has(c); },
        },
        get textContent() {
          if (this.nodeType === 3) return this._text;
          return this.children.map((c) => c.textContent).join("");
        },
        set textContent(v) {
          this.children.length = 0;
          this._text = String(v ?? "");
          if (this.nodeType !== 3 && this._text) {
            const t = makeNode("#text");
            t._text = this._text;
            t.parentNode = this;
            this.children.push(t);
          }
        },
        get options() {
          return this.tagName === "SELECT" ? this.children.filter((c) => c.tagName === "OPTION") : [];
        },
        get value() {
          if (this.tagName === "SELECT") {
            const opts = this.options;
            if (explicitValue !== undefined && opts.some((o) => o.value === explicitValue)) {
              return explicitValue;
            }
            const sel = opts.find((o) => o.selected) || opts[0];
            return sel ? sel.value : "";
          }
          return explicitValue !== undefined ? explicitValue : (this.attributes.value ?? "");
        },
        set value(v) {
          const sv = String(v ?? "");
          if (this.tagName === "SELECT") {
            const opts = this.options;
            if (opts.some((o) => o.value === sv)) {
              explicitValue = sv;
              opts.forEach((o) => { o.selected = o.value === sv; });
            } else {
              explicitValue = undefined;
            }
          } else {
            explicitValue = sv;
          }
        },
        setAttribute(k, v) {
          const sv = String(v);
          this.attributes[k] = sv;
          if (k === "id") {
            this.id = sv;
            byId.set(sv, this);
          } else if (k === "class") {
            this.className = sv;
          } else if (k === "hidden") {
            this.hidden = true;
          } else if (k === "disabled") {
            this.disabled = true;
          } else if (k === "title") {
            this.title = sv;
          } else if (k === "value") {
            explicitValue = sv;
          }
        },
        getAttribute(k) {
          return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null;
        },
        appendChild(child) {
          if (!child) return child;
          if (child.nodeType === 11) {
            for (const sub of [...child.children]) this.appendChild(sub);
            child.children.length = 0;
            return child;
          }
          if (child.parentNode && child.parentNode.children) {
            const i = child.parentNode.children.indexOf(child);
            if (i >= 0) child.parentNode.children.splice(i, 1);
          }
          child.parentNode = this;
          this.children.push(child);
          if (this.tagName === "SELECT" && child.tagName === "OPTION" && child.selected) {
            explicitValue = child.value;
          }
          return child;
        },
        removeChild(child) {
          const i = this.children.indexOf(child);
          if (i >= 0) {
            this.children.splice(i, 1);
            child.parentNode = null;
          }
          return child;
        },
        get firstChild() { return this.children[0] || null; },
        get lastChild() { return this.children[this.children.length - 1] || null; },
        contains(other) {
          let cur = other;
          while (cur) {
            if (cur === this) return true;
            cur = cur.parentNode;
          }
          return false;
        },
        matches(sel) {
          if (this.nodeType !== 1) return false;
          const s = sel.trim();
          const mOpt = s.match(/^\.([A-Za-z0-9_-]+)\[([A-Za-z0-9_-]+)="([^"]*)"\]$/);
          if (mOpt) return classes.has(mOpt[1]) && this.getAttribute(mOpt[2]) === mOpt[3];
          const mAttr = s.match(/^\[([A-Za-z0-9_-]+)(?:="([^"]*)")?\]$/);
          if (mAttr) {
            if (mAttr[2] === undefined) return this.getAttribute(mAttr[1]) !== null;
            return this.getAttribute(mAttr[1]) === mAttr[2];
          }
          if (s.startsWith("#")) return this.id === s.slice(1);
          if (s.startsWith(".")) return s.slice(1).split(".").every((c) => classes.has(c));
          return this.tagName === s.toUpperCase();
        },
        closest(sel) {
          let cur = this;
          while (cur && cur.nodeType === 1) {
            if (cur.matches(sel)) return cur;
            cur = cur.parentNode;
          }
          return null;
        },
        querySelectorAll(sel) {
          const parts = sel.split(",").map((x) => x.trim()).filter(Boolean);
          const out = [];
          const walk = (n) => {
            for (const c of n.children || []) {
              if (c.nodeType === 1 && parts.some((p) => c.matches(p))) out.push(c);
              walk(c);
            }
          };
          walk(this);
          return out;
        },
        querySelector(sel) {
          return this.querySelectorAll(sel)[0] || null;
        },
        addEventListener(type, fn) {
          listeners[type] = listeners[type] || [];
          listeners[type].push(fn);
        },
        dispatchEvent(ev) {
          if (!ev.target) ev.target = this;
          let cur = this;
          while (cur) {
            for (const fn of [...(cur._listeners?.[ev.type] || [])]) {
              fn.call(cur, ev);
            }
            if (!ev.bubbles) break;
            cur = cur.parentNode;
          }
          return !ev.defaultPrevented;
        },
        click() {
          if (this.disabled) return;
          this.dispatchEvent(new MiniEvent("click", { bubbles: true }));
        },
        focus() {},
        scrollIntoView() {},
        _listeners: listeners,
      };
      return node;
    }

    const root = makeNode("document");
    const stack = [root];
    const tokenRe = /<!--[\s\S]*?-->|<\/([A-Za-z0-9:-]+)\s*>|<([A-Za-z0-9:-]+)((?:\s+[A-Za-z0-9_:-]+(?:="[^"]*"|='[^']*'|[^\s>]*))*\s*)\/?>|([^<]+)/g;
    let m;
    while ((m = tokenRe.exec(htmlSource)) !== null) {
      if (m[1]) {
        const closeTag = m[1].toUpperCase();
        for (let i = stack.length - 1; i > 0; i--) {
          if (stack[i].tagName === closeTag) {
            stack.length = i;
            break;
          }
        }
      } else if (m[2]) {
        const tag = m[2].toLowerCase();
        if (tag === "!doctype") continue;
        const el = makeNode(tag);
        const attrRaw = m[3] || "";
        const attrRe = /([A-Za-z0-9_:-]+)(?:="([^"]*)"|='([^']*)'|=([^\s>]+))?/g;
        let am;
        while ((am = attrRe.exec(attrRaw)) !== null) {
          const val = am[2] ?? am[3] ?? am[4] ?? "";
          el.setAttribute(am[1], val);
        }
        stack[stack.length - 1].appendChild(el);
        const selfClose = m[0].endsWith("/>") || VOID_TAGS.has(tag);
        if (!selfClose) stack.push(el);
      } else if (m[4] && m[4].trim()) {
        const t = makeNode("#text");
        t._text = m[4];
        stack[stack.length - 1].appendChild(t);
      }
    }

    const docEl = root.querySelector("html") || makeNode("html");
    const docListeners = {};
    const doc = {
      readyState: "complete",
      documentElement: docEl,
      title: "",
      getElementById(id) { return byId.get(id) || null; },
      createElement(tag) { return makeNode(tag); },
      createElementNS(_ns, tag) { return makeNode(tag); },
      createDocumentFragment() { return makeNode("#fragment"); },
      createTextNode(text) { const t = makeNode("#text"); t._text = String(text ?? ""); return t; },
      querySelector(sel) { return root.querySelector(sel); },
      querySelectorAll(sel) { return root.querySelectorAll(sel); },
      addEventListener(type, fn) {
        docListeners[type] = docListeners[type] || [];
        docListeners[type].push(fn);
      },
    };
    const winListeners = {};
    const win = {
      document: doc,
      Event: MiniEvent,
      location: { search: "", href: "http://127.0.0.1:18417/", replace() {} },
      navigator: { language: "en-US" },
      addEventListener(type, fn) {
        winListeners[type] = winListeners[type] || [];
        winListeners[type].push(fn);
      },
      close() {},
    };
    win.window = win;
    win.parent = win;
    return { win, doc };
  }

  const AUX_MODELS = [
    { id: "gemini-3.8-flash", name: "Gemini 3.8 Flash", thinkingLevels: ["low", "medium", "high"], effectiveEfforts: ["low", "medium", "high"], defaultEffort: "low", supportsReasoning: true, isAliasFixed: false, fixedEffort: "" },
    { id: "gpt-oss-120b", name: "GPT OSS 120B", thinkingLevels: ["medium"], effectiveEfforts: ["medium"], defaultEffort: "medium", supportsReasoning: true, isAliasFixed: false, fixedEffort: "" },
    { id: "claude-fixed-high", name: "claude-fixed-high", thinkingLevels: [], effectiveEfforts: ["high"], defaultEffort: "high", supportsReasoning: true, isAliasFixed: true, fixedEffort: "high" },
    { id: "plain-text-model", name: "Plain Text Model", thinkingLevels: [], effectiveEfforts: [], defaultEffort: "", supportsReasoning: false, isAliasFixed: false, fixedEffort: "" },
  ];

  function auxStatePayload(over = {}) {
    return { ok: true, preserveCacheEffort: true, preserveSource: "default", catalogStatus: "ok", catalogError: "", models: AUX_MODELS, ...over };
  }

  async function mountAuxPanel({ options = {}, state = auxStatePayload(), fetchImpl = null, hosted = true, location = null, service = "" } = {}) {
    const html = fs.readFileSync(path.join(PLUGIN_ROOT, "ui/sanitizer-panel.html"), "utf8");
    const jsSource = fs.readFileSync(path.join(PLUGIN_ROOT, "ui/sanitizer-panel.js"), "utf8");
    const { win, doc } = createMiniDom(html);
    const ctl = { state, calls: [], setCalls: [], visCbs: [], replacedUrls: [] };
    win.location = {
      protocol: "http:",
      hostname: "127.0.0.1",
      search: "",
      href: "http://127.0.0.1:18417/",
      ...(location || {}),
      replace(url) {
        ctl.replacedUrls.push(String(url));
      },
    };
    const fetchFn = async (url, init) => {
      const u = String(url);
      ctl.calls.push(u);
      if (fetchImpl) {
        const custom = await fetchImpl(u, init, ctl);
        if (custom) return custom;
      }
      if (u.startsWith("api/aux-routing/state")) {
        return new Response(JSON.stringify(ctl.state), { status: 200, headers: { "content-type": "application/json" } });
      }
      throw new Error(`Unexpected fetch ${u}`);
    };
    win.fetch = fetchFn;
    if (hosted) win.__magpieServiceHosted = true;
    win.magpie = {
      service,
      ready: Promise.resolve({ lang: "en", service }),
      options: {
        get: async () => JSON.parse(JSON.stringify(options)),
        set: async (payload) => {
          ctl.setCalls.push(JSON.parse(JSON.stringify(payload)));
          return payload;
        },
      },
      onTheme() {},
      onVisibility(fn) { ctl.visCbs.push(fn); },
    };
    const sandbox = {
      window: win,
      document: doc,
      navigator: win.navigator,
      URLSearchParams,
      fetch: fetchFn,
      setTimeout,
      clearTimeout,
      Date,
      Promise,
      Error,
      Math,
      Object,
      Array,
      String,
      Boolean,
      Number,
      JSON,
      RegExp,
      parseInt,
      isNaN,
    };
    vm.runInNewContext(jsSource, sandbox);
    const settle = (ms = 60) => new Promise((r) => setTimeout(r, ms));
    await settle();
    const $ = (id) => doc.getElementById(id);
    return {
      win, doc, ctl, $, settle,
      fire(el, type) { el.dispatchEvent(new win.Event(type, { bubbles: true })); },
      type(el, value) { el.value = value; el.dispatchEvent(new win.Event("input", { bubbles: true })); },
      choose(sel, value) { sel.value = value; sel.dispatchEvent(new win.Event("change", { bubbles: true })); },
      seg(id, val) { $(id).querySelector(`.opt[data-val="${val}"]`).click(); },
      optionTexts: (sel) => Array.from(sel.options).map((o) => o.textContent),
      optionValues: (sel) => Array.from(sel.options).map((o) => o.value),
      close() { win.close(); },
    };
  }

  it("aux panel: reads CLI snake_case aux_* options (snake wins, invalid falls through) with a clean initial state", async () => {
    const p = await mountAuxPanel({
      options: {
        aux_incompatible_policy: "fallback_model",
        auxIncompatiblePolicy: "keep",
        aux_fallback_model: "gemini-3.8-flash",
        aux_fallback_effort: "THINKING_LEVEL_MEDIUM",
        aux_min_body_bytes: "abc",
        auxMinBodyBytes: "1e3",
        aux_max_output_tokens: 1000,
        auxMaxOutputTokens: 2000,
        aux_session_ttl_sec: "300",
        preserveCacheEffort: true,
        pageServicePort: 18417,
      },
    });
    try {
      assert.deepEqual(p.ctl.calls, ["api/aux-routing/state"]);
      assert.equal(p.$("sw-aux-policy").getAttribute("data-val"), "fallback_model");
      assert.equal(p.$("row-aux-model").hidden, false);
      assert.equal(p.$("row-aux-effort").hidden, false);
      assert.equal(p.$("sel-aux-model").value, "gemini-3.8-flash");
      assert.equal(p.$("sel-aux-effort").value, "medium");
      assert.equal(p.$("in-aux-min").value, "1000");
      assert.equal(p.$("in-aux-out").value, "1000");
      assert.equal(p.$("in-aux-ttl").value, "300");
      assert.equal(p.$("aux-adv-count").textContent, "3 changed");
      assert.equal(p.$("btn-save").disabled, true);
      assert.equal(p.$("dirty").hidden, true);
      assert.equal(p.$("aux-adv").hidden, true);
      assert.equal(p.$("aux-adv-toggle").getAttribute("aria-expanded"), "false");
      assert.equal(p.ctl.setCalls.length, 0);
      // model labels: name + id when they differ, bare id otherwise
      assert.deepEqual(p.optionTexts(p.$("sel-aux-model")).slice(0, 3), ["Choose a model…", "Gemini 3.8 Flash · gemini-3.8-flash", "GPT OSS 120B · gpt-oss-120b"]);
      assert.ok(p.optionTexts(p.$("sel-aux-model")).includes("claude-fixed-high"));
      assert.equal(p.$("sel-aux-model").title, "Gemini 3.8 Flash · gemini-3.8-flash");
    } finally {
      p.close();
    }
  });

  it("aux panel: defaults, fallback visibility, and effort follow the model only on user model change", async () => {
    const p = await mountAuxPanel({ options: {} });
    try {
      assert.equal(p.$("sw-aux-policy").getAttribute("data-val"), "current_low");
      assert.equal(p.$("row-aux-model").hidden, true);
      assert.equal(p.$("row-aux-effort").hidden, true);
      assert.equal(p.$("aux-adv-count").textContent, "Default");
      assert.equal(p.$("in-aux-min").placeholder, "Default 32768");

      p.seg("sw-aux-policy", "fallback_model");
      assert.equal(p.$("row-aux-model").hidden, false);
      assert.equal(p.$("btn-save").disabled, false);
      // unset model: gentle warning, saving stays possible
      assert.match(p.$("aux-model-warn").textContent, /No fallback model chosen/);
      assert.equal(p.$("aux-model-warn").hidden, false);
      assert.equal(p.$("btn-save").disabled, false);
      // no model selected: standard levels, enabled
      assert.deepEqual(p.optionValues(p.$("sel-aux-effort")), ["minimal", "low", "medium", "high", "xhigh", "max"]);
      assert.equal(p.$("sel-aux-effort").disabled, false);
      assert.equal(p.$("sel-aux-effort").value, "low");

      // single-level model: low -> medium with a note
      p.choose(p.$("sel-aux-model"), "gpt-oss-120b");
      assert.deepEqual(p.optionValues(p.$("sel-aux-effort")), ["medium"]);
      assert.equal(p.$("sel-aux-effort").value, "medium");
      assert.equal(p.$("sel-aux-effort").disabled, false);
      assert.equal(p.$("aux-effort-note").textContent, "The selected model does not support Low; switched to Medium");
      assert.equal(p.$("aux-model-warn").hidden, true);

      // medium is supported by gemini: unchanged
      p.choose(p.$("sel-aux-model"), "gemini-3.8-flash");
      assert.deepEqual(p.optionValues(p.$("sel-aux-effort")), ["low", "medium", "high"]);
      assert.equal(p.$("sel-aux-effort").value, "medium");
      assert.equal(p.$("aux-effort-note").hidden, true);

      // alias-fixed model: locked, draft untouched
      p.choose(p.$("sel-aux-model"), "claude-fixed-high");
      assert.equal(p.$("sel-aux-effort").disabled, true);
      assert.deepEqual(p.optionValues(p.$("sel-aux-effort")), ["high"]);
      assert.equal(p.$("aux-effort-note").textContent, "Effort is fixed by the model alias: high");

      // non-thinking model: disabled, draft untouched
      p.choose(p.$("sel-aux-model"), "plain-text-model");
      assert.equal(p.$("sel-aux-effort").disabled, true);
      assert.equal(p.optionTexts(p.$("sel-aux-effort"))[0], "No reasoning · stripped automatically");

      // back to a thinking model keeps the (still valid) saved effort
      p.choose(p.$("sel-aux-model"), "gemini-3.8-flash");
      p.$("btn-save").click();
      await p.settle();
      assert.equal(p.ctl.setCalls.length, 1);
      assert.equal(p.ctl.setCalls[0].auxFallbackModel, "gemini-3.8-flash");
      assert.equal(p.ctl.setCalls[0].auxFallbackEffort, "medium");
      assert.equal(p.ctl.setCalls[0].auxIncompatiblePolicy, "fallback_model");
    } finally {
      p.close();
    }
  });

  it("aux panel: refresh and visibility re-reads never change the draft; saved unknown model is kept with a catalog-aware warning", async () => {
    const p = await mountAuxPanel({
      options: { auxIncompatiblePolicy: "fallback_model", auxFallbackModel: "gpt-oss-120b", auxFallbackEffort: "low" },
    });
    try {
      // saved effort "low" is not supported by gpt-oss-120b: kept, with a runtime-adapt hint, not dirty
      assert.equal(p.$("sel-aux-effort").value, "low");
      assert.match(p.$("aux-effort-note").textContent, /will be adapted to Medium at runtime/);
      assert.equal(p.$("dirty").hidden, true);

      // catalog now lacks the saved model
      p.ctl.state = auxStatePayload({ models: AUX_MODELS.filter((m) => m.id !== "gpt-oss-120b") });
      p.$("btn-aux-refresh").click();
      await p.settle();
      assert.equal(p.ctl.calls.at(-1), "api/aux-routing/state?refresh=1");
      assert.equal(p.$("sel-aux-model").value, "gpt-oss-120b");
      assert.equal(p.optionTexts(p.$("sel-aux-model"))[1], "gpt-oss-120b (not in current catalog)");
      assert.match(p.$("aux-model-warn").textContent, /saved model is not in the current catalog/);
      assert.equal(p.$("dirty").hidden, true);
      assert.equal(p.$("btn-save").disabled, true);

      for (const [status, extra, re] of [
        ["error", { catalogError: "boom" }, /Could not load the model catalog: boom/],
        ["empty", {}, /model catalog is empty/],
        ["auth_scope_ambiguous", {}, /Multiple login scopes/],
      ]) {
        p.ctl.state = auxStatePayload({ catalogStatus: status, models: [], ...extra });
        p.$("btn-aux-refresh").click();
        await p.settle();
        assert.match(p.$("aux-model-warn").textContent, re);
        assert.equal(p.$("sel-aux-model").value, "gpt-oss-120b");
        assert.equal(p.$("dirty").hidden, true);
      }
      assert.equal(p.ctl.setCalls.length, 0);
    } finally {
      p.close();
    }
  });

  it("aux panel: master switch off shows the source-specific banner, dims the body, and refreshes silently on visibility", async () => {
    const p = await mountAuxPanel({
      options: { aux_min_body_bytes: 1024 },
      state: auxStatePayload({ preserveCacheEffort: false, preserveSource: "provider_ui" }),
    });
    try {
      assert.equal(p.$("aux-off").hidden, false);
      assert.match(p.$("aux-off-src").textContent, /Provider dialog/);
      assert.equal(p.$("aux-body").classList.contains("inactive"), true);
      assert.equal(p.$("aux-adv").classList.contains("inactive"), true);
      // the banner is outside the dimmed body so it stays crisp
      assert.equal(p.$("aux-body").contains(p.$("aux-off")), false);
      // still editable while inactive
      p.type(p.$("in-aux-ttl"), "120");
      assert.equal(p.$("dirty").hidden, false);
      p.$("btn-revert").click();
      assert.equal(p.$("in-aux-ttl").value, "600");

      p.ctl.state = auxStatePayload({ preserveCacheEffort: false, preserveSource: "plugins_json" });
      p.ctl.visCbs.forEach((fn) => fn(true));
      await p.settle();
      assert.match(p.$("aux-off-src").textContent, /plugins\.json/);
      p.ctl.state = auxStatePayload({ preserveCacheEffort: false, preserveSource: "default" });
      p.ctl.visCbs.forEach((fn) => fn(true));
      await p.settle();
      assert.match(p.$("aux-off-src").textContent, /not managed by a Provider/);

      // flipped back on in the Provider dialog: banner clears with no dirty state or draft change
      p.type(p.$("in-aux-min"), "2048");
      p.ctl.state = auxStatePayload({ preserveCacheEffort: true, preserveSource: "provider_ui" });
      p.ctl.visCbs.forEach((fn) => fn(true));
      await p.settle();
      assert.equal(p.$("aux-off").hidden, true);
      assert.equal(p.$("aux-body").classList.contains("inactive"), false);
      assert.equal(p.$("in-aux-min").value, "2048");
      assert.deepEqual(p.ctl.calls.filter((u) => u.includes("refresh")), []);
      p.ctl.visCbs.forEach((fn) => fn(false));
      await p.settle();
      // init + three visible events fetched; the hidden event must not
      assert.equal(p.ctl.calls.length, 4);
    } finally {
      p.close();
    }
  });

  it("aux panel: invalid numbers block save, valid edits save canonical camelCase only, and rules actions never touch aux", async () => {
    const customRule = { id: "keep-me", pattern: "foo", replacement: "bar", scope: "all", enabled: true };
    const p = await mountAuxPanel({
      options: {
        promptSanitizer: true,
        promptRewrite: { enabled: true, normalize_identity: true, sideload_mode: "off", sanitize_tools_description: true, rules: [customRule] },
        aux_incompatible_policy: "current_low",
        auxIncompatiblePolicy: "keep",
        aux_fallback_model: "gemini-3.8-flash",
        aux_fallback_effort: "high",
        aux_min_body_bytes: 65536,
        auxMaxOutputTokens: 4096,
        aux_session_ttl_sec: 300,
        preserve_cache_effort: false,
        pageServicePort: 18417,
        cacheTtlSec: 10,
      },
      fetchImpl: async (u) =>
        u === "api/upstream-presets"
          ? new Response(JSON.stringify({ ok: true, rules: [{ id: "up", pattern: "abc", replacement: "", scope: "all", enabled: true }] }), { status: 200, headers: { "content-type": "application/json" } })
          : null,
    });
    try {
      const save = p.$("btn-save");
      const row = p.$("row-aux-min");
      // advanced section is collapsed; an invalid edit must surface it
      p.$("aux-adv-toggle").click();
      assert.equal(p.$("aux-adv").hidden, false);
      p.$("aux-adv-toggle").click();
      assert.equal(p.$("aux-adv").hidden, true);

      for (const bad of ["-5", "1.5", "abc", "6291457", "1e3"]) {
        p.type(p.$("in-aux-min"), bad);
        assert.equal(row.classList.contains("invalid"), true, bad);
        assert.equal(p.$("warn-aux-min").textContent, "Enter an integer from 0 to 6291456");
        assert.equal(p.$("aux-adv").hidden, false);
        assert.equal(save.disabled, true, bad);
        assert.equal(p.$("status").textContent, "1 invalid value(s). Fix them to save.");
        p.$("aux-adv-toggle").click();   // cannot hide an invalid value
        assert.equal(p.$("aux-adv").hidden, false);
      }
      // empty means default (valid, dirty vs 65536); typing a valid integer is saveable
      p.type(p.$("in-aux-min"), "");
      assert.equal(row.classList.contains("invalid"), false);
      assert.equal(save.disabled, false);
      // whitespace-only input saved WITHOUT blur resolves cleanly to numeric default (never NaN/null)
      p.type(p.$("in-aux-out"), "   ");
      assert.equal(save.disabled, false);
      save.click();
      await p.settle();
      assert.strictEqual(p.ctl.setCalls.at(-1).auxMaxOutputTokens, 8192);
      p.type(p.$("in-aux-out"), "4096");

      p.type(p.$("in-aux-min"), "00131072");
      p.fire(p.$("in-aux-min"), "blur");
      assert.equal(p.$("in-aux-min").value, "131072");
      p.seg("sw-aux-policy", "keep");
      assert.equal(save.disabled, false);

      // rules actions leave aux untouched
      const auxSnapshot = () => ["in-aux-min", "in-aux-out", "in-aux-ttl"].map((id) => p.$(id).value).concat(p.$("sw-aux-policy").getAttribute("data-val"), p.$("sel-aux-effort").value);
      const before = auxSnapshot();
      p.$("btn-reset").click();
      p.$("btn-reset").click();
      assert.equal(p.$("rules-list").querySelectorAll(".row.rule").length, RECOMMENDED_PRESET_RULES.length);
      assert.deepEqual(auxSnapshot(), before);
      p.$("btn-sync-upstream").click();
      p.$("btn-sync-upstream").click();
      await p.settle(120);
      assert.equal(p.$("rules-list").querySelectorAll(".row.rule").length, 1);
      assert.deepEqual(auxSnapshot(), before);

      save.click();
      await p.settle();
      assert.equal(p.ctl.setCalls.length, 2);
      const out = p.ctl.setCalls[1];
      for (const k of ["aux_incompatible_policy", "aux_fallback_model", "aux_fallback_effort", "aux_min_body_bytes", "aux_max_output_tokens", "aux_session_ttl_sec"]) {
        assert.equal(k in out, false, k);
      }
      assert.equal(out.auxIncompatiblePolicy, "keep");
      assert.equal(out.auxFallbackModel, "gemini-3.8-flash");
      assert.equal(out.auxFallbackEffort, "high");
      assert.strictEqual(out.auxMinBodyBytes, 131072);
      assert.strictEqual(out.auxMaxOutputTokens, 4096);
      assert.strictEqual(out.auxSessionTtlSec, 300);
      // unrelated keys, including the master switch, are carried over verbatim
      assert.strictEqual(out.preserve_cache_effort, false);
      assert.equal("preserveCacheEffort" in out, false);
      assert.equal(out.pageServicePort, 18417);
      assert.equal(out.cacheTtlSec, 10);
      assert.equal(out.promptRewrite.rules[0].id, "up");
      assert.equal(p.$("dirty").hidden, true);
      assert.equal(save.disabled, true);

      // aux defaults: two-step, aux only
      const rulesBefore = p.$("rules-list").querySelectorAll(".row.rule").length;
      p.$("btn-aux-defaults").click();
      assert.equal(p.$("btn-aux-defaults").textContent, "Confirm restore?");
      assert.equal(p.$("in-aux-min").value, "131072");
      p.$("btn-aux-defaults").click();
      assert.equal(p.$("sw-aux-policy").getAttribute("data-val"), "current_low");
      assert.deepEqual(["in-aux-min", "in-aux-out", "in-aux-ttl"].map((id) => p.$(id).value), ["32768", "8192", "600"]);
      assert.equal(p.$("btn-aux-defaults").textContent, "Restore defaults");
      assert.equal(p.$("aux-adv-count").textContent, "Default");
      assert.equal(p.$("rules-list").querySelectorAll(".row.rule").length, rulesBefore);
      assert.equal(p.$("dirty").hidden, false);
    } finally {
      p.close();
    }
  });

  it("aux panel: api/aux-routing/state wakes a dormant service on non-JSON 502 and retries once", async () => {
    let stateAttempts = 0;
    const p = await mountAuxPanel({
      options: {},
      fetchImpl: async (u) => {
        if (u === "api/aux-routing/state") {
          stateAttempts += 1;
          if (stateAttempts === 1) return new Response("502 Bad Gateway (dormant)", { status: 502, headers: { "content-type": "text/plain" } });
          return null;
        }
        if (u === "./") return new Response("<html></html>", { status: 200 });
        if (u === "health") return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
        return null;
      },
    });
    try {
      await p.settle(120);
      assert.deepEqual(p.ctl.calls, ["api/aux-routing/state", "./", "health", "api/aux-routing/state"]);
      p.seg("sw-aux-policy", "fallback_model");
      assert.equal(p.optionValues(p.$("sel-aux-model")).includes("gpt-oss-120b"), true);
    } finally {
      p.close();
    }
  });

  it("aux panel: unhosted pages never call the state API and disable catalog refresh", async () => {
    const p = await mountAuxPanel({
      options: { auxFallbackModel: "saved-model", auxIncompatiblePolicy: "fallback_model" },
      hosted: false,
      location: { protocol: "https:", hostname: "magpie.example.com", href: "https://magpie.example.com/_magpie/plugin/tok/sanitizer-panel.html" },
    });
    try {
      // magpie.service is absent on a remote browser, so the page stays put and never redirects to 127.0.0.1
      assert.deepEqual(p.ctl.replacedUrls, []);
      assert.deepEqual(p.ctl.calls, []);
      assert.equal(p.$("app").hidden, false);
      assert.equal(p.$("btn-aux-refresh").disabled, true);
      assert.equal(p.$("btn-aux-refresh").title, "Requires Magpie page service to fetch upstream");
      assert.equal(p.$("sel-aux-model").value, "saved-model");
      assert.equal(p.optionTexts(p.$("sel-aux-model"))[1], "saved-model");
    } finally {
      p.close();
    }
  });

  it("desktop window handoff: redirects wails://localhost and http://wails.localhost to local pageServicePort, honors disablePageService, and reveals fallback UI if WebKit refuses navigation", async () => {
    // 1. macOS / Linux desktop (`wails://localhost`) -> default 18417, keeps #app hidden during handoff, then reveals if refused
    const macDefault = await mountAuxPanel({
      options: {},
      hosted: false,
      location: {
        protocol: "wails:",
        hostname: "localhost",
        href: "wails://localhost/_magpie/plugin/tok/sanitizer-panel.html",
      },
    });
    try {
      assert.deepEqual(macDefault.ctl.replacedUrls, ["http://127.0.0.1:18417/"]);
      assert.equal(macDefault.$("app").hidden, true);
      // Simulate WebKit leaving the frame on the static document when loopback is refused
      await macDefault.settle(850);
      assert.equal(macDefault.$("app").hidden, false);
    } finally {
      macDefault.close();
    }

    // 2. macOS desktop with custom `pageServicePort`
    const macCustomPort = await mountAuxPanel({
      options: { pageServicePort: "19417" },
      hosted: false,
      location: {
        protocol: "wails:",
        hostname: "localhost",
        href: "wails://localhost/_magpie/plugin/tok/sanitizer-panel.html",
      },
    });
    try {
      assert.deepEqual(macCustomPort.ctl.replacedUrls, ["http://127.0.0.1:19417/"]);
    } finally {
      macCustomPort.close();
    }

    // 3. Windows desktop (`http://wails.localhost`) -> redirects to loopback service
    const winDesktop = await mountAuxPanel({
      options: {},
      hosted: false,
      location: {
        protocol: "http:",
        hostname: "wails.localhost",
        href: "http://wails.localhost/_magpie/plugin/tok/sanitizer-panel.html?_o=http%3A%2F%2Fwails.localhost",
      },
    });
    try {
      assert.deepEqual(winDesktop.ctl.replacedUrls, ["http://127.0.0.1:18417/"]);
    } finally {
      winDesktop.close();
    }

    // 4. Desktop with `disablePageService: true` -> stays on static page and reveals #app immediately
    const desktopDisabled = await mountAuxPanel({
      options: { disablePageService: true },
      hosted: false,
      location: {
        protocol: "wails:",
        hostname: "localhost",
        href: "wails://localhost/_magpie/plugin/tok/sanitizer-panel.html",
      },
    });
    try {
      assert.deepEqual(desktopDisabled.ctl.replacedUrls, []);
      assert.equal(desktopDisabled.$("app").hidden, false);
    } finally {
      desktopDisabled.close();
    }

    // 5. `magpie web` with `magpie.service` -> redirects immediately to the proxy path
    const webProxied = await mountAuxPanel({
      options: {},
      hosted: false,
      service: "https://magpie.example.com/_magpie/plugin/tok/_magpie/service/",
      location: {
        protocol: "https:",
        hostname: "magpie.example.com",
        href: "https://magpie.example.com/_magpie/plugin/tok/sanitizer-panel.html",
      },
    });
    try {
      assert.deepEqual(webProxied.ctl.replacedUrls, [
        "https://magpie.example.com/_magpie/plugin/tok/_magpie/service/",
      ]);
    } finally {
      webProxied.close();
    }
  });
});
