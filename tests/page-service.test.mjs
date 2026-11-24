import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  DEFAULT_PAGE_SERVICE_PORT,
  MAX_PATTERN_CHARS,
  MAX_REPLACEMENT_CHARS,
  MAX_RULES,
  MAX_UPSTREAM_BODY_BYTES,
  UPSTREAM_AGT_BETA_CONFIG_URL,
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
    for (const htmlPath of ["/", "/index.html", "/sanitizer-panel.html"]) {
      const htmlRes = await fetch(`${base}${htmlPath}`);
      assert.equal(htmlRes.status, 200);
      assert.match(htmlRes.headers.get("content-type") || "", /^text\/html/);
      assert.equal(
        htmlRes.headers.get("content-security-policy"),
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'self'",
      );
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
    // Wait briefly for fire-and-forget startup inside server()
    await new Promise((resolve) => setTimeout(resolve, 30));
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
});
