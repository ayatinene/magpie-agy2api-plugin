import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  DEFAULT_PAGE_SERVICE_PORT,
  MAX_RULES,
  UPSTREAM_AGT_BETA_CONFIG_URL,
  fetchUpstreamPresetRules,
  parseRustPresetRules,
  startPageService,
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

  it("caps parsed rules at MAX_RULES and skips invalid empty id/pattern entries", () => {
    const items = [
      `PromptRewriteRule::with_scope("", "*bad*", "", PromptRewriteScope::Prompt, true),`,
      `PromptRewriteRule::with_scope("empty-pattern", "", "", PromptRewriteScope::Prompt, true),`,
    ];
    for (let idx = 0; idx < MAX_RULES + 10; idx += 1) {
      items.push(
        `PromptRewriteRule::with_scope("rule-${idx}", "pat-${idx}", "", PromptRewriteScope::Prompt, true),`,
      );
    }
    const rustSrc = `fn recommended_preset_rules() -> Vec<PromptRewriteRule> { vec![\n${items.join("\n")}\n] }`;
    const rules = parseRustPresetRules(rustSrc);
    assert.equal(rules.length, MAX_RULES);
    assert.equal(rules[0].id, "rule-0");
    assert.equal(rules[MAX_RULES - 1].id, `rule-${MAX_RULES - 1}`);
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
    let failUpstream = false;

    const svc = await startPageService({
      port,
      fetchImpl: async () => {
        if (failUpstream) {
          return new Response("upstream down", { status: 503, statusText: "Service Unavailable" });
        }
        return new Response(REAL_AGT_BETA_CONFIG_SNIPPET, { status: 200 });
      },
    });
    cleanups.push(() => svc.close());

    assert.equal(svc.ok, true);
    assert.equal(svc.port, port);

    const registry = globalThis[Symbol.for("magpie.agy2api.pageServices")];
    assert.ok(registry instanceof Map);
    assert.equal(registry.get(port)?.server, svc.server);

    // Reload / duplicate start on same port reuses cleanly without EADDRINUSE
    const reused = await startPageService({ port });
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

    // 4. GET & POST /api/upstream-presets success + CORS headers for sandboxed Origin: null iframe
    const optRes = await fetch(`${base}/api/upstream-presets`, { method: "OPTIONS" });
    assert.equal(optRes.status, 204);
    assert.equal(optRes.headers.get("access-control-allow-origin"), "*");
    for (const method of ["GET", "POST"]) {
      const apiRes = await fetch(`${base}/api/upstream-presets`, { method });
      assert.equal(apiRes.status, 200);
      assert.equal(apiRes.headers.get("access-control-allow-origin"), "*");
      const data = await apiRes.json();
      assert.equal(data.ok, true);
      assert.equal(data.branch, "beta");
      assert.equal(data.count, 12);
      assert.deepEqual(data.rules, RECOMMENDED_PRESET_RULES);
    }

    // 5. Upstream failure -> 502 JSON
    failUpstream = true;
    const errRes = await fetch(`${base}/api/upstream-presets`);
    assert.equal(errRes.status, 502);
    const errJson = await errRes.json();
    assert.equal(errJson.ok, false);
    assert.match(errJson.error, /503/);

    // 6. Unknown path -> 404
    const notFoundRes = await fetch(`${base}/does-not-exist`);
    assert.equal(notFoundRes.status, 404);
    assert.deepEqual(await notFoundRes.json(), { ok: false, error: "Not found" });

    await svc.close();
    assert.equal(registry.has(port), false);
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

  it("wires package.json magpie.page.service and index.mjs disablePageService option", async () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(PLUGIN_ROOT, "package.json"), "utf8"));
    assert.deepEqual(pkg.magpie?.page?.service, {
      port: DEFAULT_PAGE_SERVICE_PORT,
      option: "pageServicePort",
    });

    const hooks = await plugin.server({}, { disablePageService: true });
    assert.equal(hooks.provider.id, "agy2api");
  });
});
