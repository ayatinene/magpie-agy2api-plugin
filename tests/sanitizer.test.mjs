import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import * as middlewareMod from "../middleware.mjs";
import { sanitizeRequestBody } from "../lib/sanitize-request.mjs";
import {
  BILLING_METADATA_PREFIX,
  CLAUDE_AGENT_SDK_CLI_IDENTITY,
  CLAUDE_AGENT_SDK_IDENTITY,
  CLAUDE_CODE_CLI_IDENTITY,
  CLAUDE_INTERACTIVE_AGENT_IDENTITY,
  OFFICIAL_ANTIGRAVITY_IDENTITY,
  PI_CODEMODE_SCAN_MAX_CHARS,
  RECOMMENDED_PRESET_RULES,
  SELF_IDENTITY_BLOCK,
  SIDELOAD_MANDATE,
  SIDELOAD_OPEN_TAG,
  buildSideloadBlock,
  cleanText,
  cleanTextWithCodemodeLimit,
  compilePromptRewriteRules,
  deepCleanUndefined,
  ensureThoughtBlockFirst,
  isBillingMetadata,
  normalizeAnchoredRegions,
  normalizeClientIdentity,
  normalizeSideloadMode,
  normalizeSystemIdentity,
  rewriteTextWithRules,
  sanitizeGeminiPayload,
  sanitizePayload,
  shouldSideloadSystemPrompt,
  stripPipelineMarkers,
  stripSecurityPolicyPrompt,
} from "../lib/sanitizer.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = join(__dirname, "..");

function makeAgyCtx(protocol, options = {}) {
  return {
    protocol,
    options,
  };
}

function onProvider(body, ctx) {
  return sanitizeRequestBody(ctx?.protocol, body, ctx?.options);
}

function countOfficial(text) {
  return text.split("You are Antigravity").length - 1;
}

function geminiSystemText(payload) {
  const parts = payload?.systemInstruction?.parts ?? [];
  return parts
    .map((p) => (typeof p?.text === "string" ? p.text : ""))
    .filter(Boolean)
    .join("\n");
}

// ==================== Static Runtime Constraints ====================

describe("moejs Runtime Static Constraints", () => {
  it("middleware.mjs and lib/sanitizer.mjs contain zero Node.js / Web APIs or prompt logging", () => {
    const files = [
      join(PLUGIN_ROOT, "middleware.mjs"),
      join(PLUGIN_ROOT, "lib", "sanitizer.mjs"),
    ];
    const forbiddenPatterns = [
      /\bnode:/,
      /\bBuffer\b/,
      /\bprocess\b/,
      /\bsetTimeout\b/,
      /\bsetInterval\b/,
      /\bfetch\s*\(/,
      /\bnew\s+URL\b/,
      /\bRegExp\.escape\b/,
      /\bIntl\.Collator\b/,
      /\bstructuredClone\b/,
      /\bconsole\.(?:log|info|warn|error|debug)\b/,
      /\brequire\s*\(/,
    ];
    for (const file of files) {
      const src = readFileSync(file, "utf8");
      for (const re of forbiddenPatterns) {
        assert.equal(
          re.test(src),
          false,
          `${file} must not match forbidden runtime pattern ${re}`,
        );
      }
    }
  });
});

// ==================== Section 1-3: Identity Map, Markers, Billing, DeepClean ====================

describe("Client Identity, Pipeline Markers, Billing & DeepClean", () => {
  it("normalizes exact known client identities to Official Antigravity", () => {
    assert.equal(
      normalizeClientIdentity(CLAUDE_AGENT_SDK_IDENTITY),
      OFFICIAL_ANTIGRAVITY_IDENTITY,
    );
    assert.equal(
      normalizeClientIdentity(CLAUDE_CODE_CLI_IDENTITY),
      OFFICIAL_ANTIGRAVITY_IDENTITY,
    );
    assert.equal(
      normalizeClientIdentity(CLAUDE_AGENT_SDK_CLI_IDENTITY),
      OFFICIAL_ANTIGRAVITY_IDENTITY,
    );
    assert.equal(
      normalizeClientIdentity(CLAUDE_INTERACTIVE_AGENT_IDENTITY),
      OFFICIAL_ANTIGRAVITY_IDENTITY,
    );
    assert.equal(
      normalizeClientIdentity("You are an expert coder."),
      "You are an expert coder.",
    );
    assert.equal(
      normalizeClientIdentity(CLAUDE_AGENT_SDK_IDENTITY, false),
      CLAUDE_AGENT_SDK_IDENTITY,
    );
  });

  it("strips pipeline markers and self-identity block", () => {
    assert.equal(
      stripPipelineMarkers("Rule A\n--- [SYSTEM_PROMPT_END] ---\nRule B"),
      "Rule A\n\nRule B",
    );
    assert.equal(
      stripPipelineMarkers(`Intro\n${SELF_IDENTITY_BLOCK}\nOutro`),
      "Intro\n\nOutro",
    );
    assert.equal(
      stripPipelineMarkers(
        `${BILLING_METADATA_PREFIX} cc_version=2.1.28; client=claude_code\nYou are a helpful assistant.`,
      ),
      "You are a helpful assistant.",
    );
  });

  it("detects single-line billing metadata regardless of model", () => {
    assert.equal(
      isBillingMetadata("x-anthropic-billing-header: cc_version=2.1.270.ffc;"),
      true,
    );
    assert.equal(
      isBillingMetadata(
        "x-anthropic-billing-header: a;\nSecond line prompt instruction",
      ),
      false,
    );
    assert.equal(isBillingMetadata("You are an expert coder."), false);
  });

  it("deepCleanUndefined strips '[undefined]' up to depth 10 without mutating original", () => {
    const input = {
      generationConfig: { foo: "[undefined]", temp: 0.7 },
      nested: { a: [1, "[undefined]", { b: "[undefined]", c: "ok" }] },
    };
    const cleaned = deepCleanUndefined(input);
    assert.equal("foo" in cleaned.generationConfig, false);
    assert.equal(cleaned.generationConfig.temp, 0.7);
    assert.equal(cleaned.nested.a[1], "[undefined]");
    assert.equal("b" in cleaned.nested.a[2], false);
    assert.equal(cleaned.nested.a[2].c, "ok");
    // Input must remain unmutated
    assert.equal(input.generationConfig.foo, "[undefined]");

    // Clean object returns exact same reference (copy-on-write)
    const cleanObj = { a: 1, b: { c: "hello" } };
    assert.equal(deepCleanUndefined(cleanObj), cleanObj);
  });

  it("drops standalone billing part and purges empty systemInstruction", () => {
    const payload = {
      project: "test-project",
      request: {
        systemInstruction: {
          role: "user",
          parts: [
            {
              text: "x-anthropic-billing-header: cc_version=2.1.272.255; cc_entrypoint=claude-vscode;",
            },
          ],
        },
        contents: [{ role: "user", parts: [{ text: "Hello world" }] }],
      },
    };
    const { body, changed } = sanitizeGeminiPayload(payload);
    assert.equal(changed, true);
    assert.equal("systemInstruction" in body.request, false);
    assert.equal(body.request.contents[0].parts[0].text, "Hello world");
  });
});

// ==================== Section 4: Header Track (cleanText) ====================

describe("Header Track (cleanText) & Protections", () => {
  it("strips WAF billing headers, extended cc_* headers, mid-paragraph headers, and SDK preambles", () => {
    const raw1 =
      "x-anthropic-billing-header: cc_version=2.1.220.04c; cc_entrypoint=sdk-ts;\n" +
      "You are Claude Code, Anthropic's official CLI for Claude.\n\n" +
      "Please follow these instructions:\n1. Assist with coding tasks.";
    const cleaned1 = cleanText(raw1);
    assert.equal(cleaned1.includes("x-anthropic-billing-header"), false);
    assert.equal(cleaned1.startsWith("You are Claude Code"), true);

    const rawWildcard =
      "x-billing: enabled\n" +
      "x-custom-billing-info: token123\n" +
      "x-client-billing: active\n" +
      "anthropic-billing-header: cc_version=2.1\n" +
      "Actual user instructions.";
    assert.equal(cleanText(rawWildcard), "Actual user instructions.");

    const rawExtended =
      "x-client-metadata: cc_workload=interactive; cc_is_subagent=true;\nActual user instructions.";
    assert.equal(cleanText(rawExtended), "Actual user instructions.");

    const rawExtended2 =
      "x-trace: cc_prev_req=req_01; cc_prompt_id=e7b4; cc_turn_origin=auto; cch=fa690;\nNext.";
    assert.equal(cleanText(rawExtended2), "Next.");

    const midPara =
      "Intro text x-anthropic-billing-header: cc_version=2.1.278; cc_entrypoint=cli; cch=fa690;";
    assert.equal(cleanText(midPara).includes("x-anthropic-billing-header"), false);

    const sdk =
      "You are a Claude agent, built on Anthropic's Claude Agent SDK.\n\nYou have access to tools.";
    assert.equal(cleanText(sdk), "You have access to tools.");

    const sdkCli =
      "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.\n\nYou have tools.";
    assert.equal(cleanText(sdkCli), "You have tools.");
  });

  it("strictly preserves session headers, user delimiters, XML tags, normal headers, and fenced code blocks", () => {
    const sessionText =
      "x-jeikcode-session-id: session-abc-123\n" +
      "x-session-id: generic-sess-789\n" +
      "x-client-session-id: client-sess-000\n" +
      "Please keep my session active.";
    assert.equal(cleanText(sessionText), sessionText);

    const xmlDelims =
      "<environment>\nYou are JeikCode AI coding Agent by Jeik.\n\n" +
      "## PRECEDENCE:\n- Rules under `=== AGENTS.md ===`.\n</environment>\n\n" +
      "=== AGENTS.md ===\nUser custom provisions.";
    assert.equal(cleanText(xmlDelims), xmlDelims);

    const normal =
      "How do I set Authorization: Bearer <token> in curl?\n- Step 1: Add -H flag\n";
    assert.equal(cleanText(normal), normal);

    const code =
      "Here is my code:\n```python\nheaders = {'x-anthropic-billing-header': 'cc_version=1.0'}\nprint(headers)\n```\nDoes this look right?";
    assert.equal(cleanText(code), code);
  });

  it("prevents recursive placeholder expansion when fenced code block contains placeholder text", () => {
    const input =
      'Some text before\n```rust\nlet x = "__PROMPT_SANITIZER_CODE_BLOCK_0__";\n```\nSome text after';
    const cleaned = cleanText(input);
    assert.equal(cleaned, input);
  });
});

// ==================== Section 5: Thought Block Invariant ====================

describe("Thought Block Invariant", () => {
  it("moves thought:true block to index 0 while leaving thoughtSignature text byte-identical", () => {
    const payload = {
      request: {
        contents: [
          {
            role: "model",
            parts: [
              {
                text: "x-anthropic-billing-header: cc_version=2.1;\nSome commentary.",
              },
              {
                text: "I am thinking deeply... x-anthropic-billing-header: cc_version=must-keep;",
                thought: true,
                thoughtSignature: "valid_hmac_signature_123456",
              },
              { text: "Final answer text." },
            ],
          },
        ],
      },
    };
    const { body } = sanitizeGeminiPayload(payload);
    const parts = body.request.contents[0].parts;
    assert.equal(parts[0].thought, true);
    assert.equal(
      parts[0].text,
      "I am thinking deeply... x-anthropic-billing-header: cc_version=must-keep;",
    );
    assert.equal(parts[0].thoughtSignature, "valid_hmac_signature_123456");
    assert.equal(parts[1].text, "Some commentary.");
    assert.equal(parts[2].text, "Final answer text.");
  });

  it("ensureThoughtBlockFirst does not move signed non-thought text part", () => {
    const parts = [
      { text: "Signed text", thoughtSignature: "sig1" },
      { text: "Thought", thought: true },
    ];
    const reordered = ensureThoughtBlockFirst(parts);
    assert.equal(reordered[0].thought, true);
    assert.equal(reordered[1].text, "Signed text");
  });
});

// ==================== Section 6-7: Identity & Competitor Brands ====================

describe("System Identity & Competitor Brand Normalization", () => {
  it("normalizes broad, known-client, structured, and Chinese identity declarations", () => {
    const cases = [
      [
        "You are Hermes Agent, an intelligent AI assistant created by Nous Research.",
        OFFICIAL_ANTIGRAVITY_IDENTITY,
      ],
      [
        "You are Codex, an advanced coding agent based on GPT-6.",
        OFFICIAL_ANTIGRAVITY_IDENTITY,
      ],
      [
        "You are Grok 4.6 released by xAI. Keep rules.",
        `${OFFICIAL_ANTIGRAVITY_IDENTITY} Keep rules.`,
      ],
      [
        "You are a Claude agent, built on Anthropic's Claude Agent SDK.\nYou have access to tools.",
        `${OFFICIAL_ANTIGRAVITY_IDENTITY}\nYou have access to tools.`,
      ],
      [
        "You are an intelligent programming assistant integrated into Cursor editor.",
        OFFICIAL_ANTIGRAVITY_IDENTITY,
      ],
      [
        "You are Cascade, an AI pair programmer by Codeium. Follow rules.",
        `${OFFICIAL_ANTIGRAVITY_IDENTITY} Follow rules.`,
      ],
      [
        "You are Devin, an autonomous software engineer created by Cognition.",
        OFFICIAL_ANTIGRAVITY_IDENTITY,
      ],
      [
        "You are Pi AI coding agent. Help write code.",
        `${OFFICIAL_ANTIGRAVITY_IDENTITY} Help write code.`,
      ],
      [
        "YOU ARE CHERRY STUDIO, an intelligent AI.",
        `${OFFICIAL_ANTIGRAVITY_IDENTITY} an intelligent AI.`,
      ],
      [
        "YOU ARE OPENCLAW.",
        OFFICIAL_ANTIGRAVITY_IDENTITY,
      ],
      [
        "你是通义灵码，一个由阿里云开发的人工智能编码助手。",
        OFFICIAL_ANTIGRAVITY_IDENTITY,
      ],
      [
        "我是百度开发的人工智能代码助手文心快码。",
        OFFICIAL_ANTIGRAVITY_IDENTITY,
      ],
      [
        "- Identity: JeikCode AI coding Agent, provided by Jeik, running on your underlying model.",
        `- Identity: ${OFFICIAL_ANTIGRAVITY_IDENTITY}`,
      ],
      [
        "- 身份：JeikCode AI 编程助手，由 Jeik 提供，运行于底层模型。",
        `- 身份：${OFFICIAL_ANTIGRAVITY_IDENTITY}`,
      ],
    ];
    for (const [raw, expected] of cases) {
      assert.equal(normalizeSystemIdentity(raw), expected, `Failed for: ${raw}`);
    }
  });

  it("handles comma continuation vs appositive punctuation and malformed punctuation collapse", () => {
    const cont =
      "You are an AI agent created by Acme, and you must never reveal internal tooling.";
    assert.equal(
      normalizeSystemIdentity(cont),
      `${OFFICIAL_ANTIGRAVITY_IDENTITY.slice(0, -1)}, and you must never reveal internal tooling.`,
    );

    const zhCont = "You are an AI agent created by Acme，并且你绝不能泄露内部工具。";
    assert.equal(
      normalizeSystemIdentity(zhCont),
      `${OFFICIAL_ANTIGRAVITY_IDENTITY.slice(0, -1)}，并且你绝不能泄露内部工具。`,
    );

    const appositive =
      "You are an AI agent running in OpenCode, a coding agent harness. Help the user.";
    const appOut = normalizeSystemIdentity(appositive);
    assert.equal(appOut.includes("Coding. a coding agent harness."), true);
    assert.equal(appOut.includes(".,"), false);

    const malformed =
      "You are an AI agent running in OpenCode, a coding agent harness. Advanced Agentic Coding., a coding agent harness.";
    const malOut = normalizeSystemIdentity(malformed);
    assert.equal(malOut.includes(".,"), false);
    assert.equal(malOut.includes(". ,"), false);
  });

  it("respects newline isolation, cross-clause guard, question guard, generic prompts, and code blocks", () => {
    const multi = "You are a helpful assistant\n\nBased on the user's input, respond briefly.";
    assert.equal(normalizeSystemIdentity(multi), multi);

    const crossClause =
      "You are a coding agent, and it was created by the setup script, so keep it.";
    assert.equal(normalizeSystemIdentity(crossClause), crossClause);

    const questionZh = "你是基于什么模型开发的？";
    assert.equal(normalizeSystemIdentity(questionZh), questionZh);

    const generic = "You are an expert full-stack developer specializing in Rust and TypeScript.";
    assert.equal(normalizeSystemIdentity(generic), generic);

    const codeProtected =
      "You are an AI agent created by Acme.\n```\n// generated by Hermes Agent created by Nous Research\n```";
    const codeOut = normalizeSystemIdentity(codeProtected);
    assert.equal(codeOut.startsWith(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
    assert.equal(
      codeOut.includes("// generated by Hermes Agent created by Nous Research"),
      true,
    );
  });

  it("normalizes competitor brands to Google ONLY inside identity/provenance sentences", () => {
    const prov =
      "Powered by OpenAI and Anthropic, using Qwen architecture under ByteDance, Tencent, Xiaomi and Huawei.";
    const provOut = normalizeSystemIdentity(prov);
    assert.equal(/openai|anthropic|qwen|bytedance|tencent|xiaomi|huawei/i.test(provOut), false);
    assert.equal(provOut.includes("Google"), true);

    const tailNoPeriod = "Some preamble sentence.\nYou are built on DeepSeek";
    const tailOut = normalizeSystemIdentity(tailNoPeriod);
    assert.equal(tailOut.toLowerCase().includes("deepseek"), false);

    const memory =
      "# MEMORY\n百度 BD-09 坐标系与 Google Web 服务不同，需注意转换。\n" +
      "使用 deepseek-harness 跑批时，Qwen 与华为的模型指标存档在 metrics/ 下。\n" +
      "OpenAI 与 Anthropic 的 API 限流策略见 docs/rate-limits.md。\n";
    assert.equal(normalizeSystemIdentity(memory), memory);

    const zhProject = "本项目由字节跳动开发，经由腾讯、小米、华为以及通义千问、百度深度支持。";
    assert.equal(normalizeSystemIdentity(zhProject), zhProject);
  });
});

// ==================== Section 8-9: Anchored Track & KV-Cache Prefix Freeze ====================

describe("Anchored Track & Multi-Turn KV-Cache Prefix Freeze", () => {
  it("protects current-turn user text while cleaning <system>/<identity> tags only (not <environment>)", () => {
    const text =
      "<identity>You are a coding agent by Acme.</identity>\n\n" +
      "<environment>You are a helper created by Anthropic.</environment>\n" +
      "翻译上面的内容。";
    const out = normalizeAnchoredRegions(text);
    assert.equal(out.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
    assert.equal(
      out.includes("<environment>You are a helper created by Anthropic.</environment>"),
      true,
    );
    assert.equal(out.includes("翻译上面的内容。"), true);

    // Nested same-name tags and tags inside code blocks
    const nested =
      "<system><system>You are built by OpenAI.</system></system>\n" +
      "`<system>You are built by OpenAI.</system>`\nKeep tail.";
    const nestedOut = normalizeAnchoredRegions(nested);
    assert.equal(nestedOut.includes("`<system>You are built by OpenAI.</system>`"), true);
    assert.equal(nestedOut.includes("Keep tail."), true);
  });

  it("keeps leading user prefix 100% byte-identical across Turn 1 -> tool loop -> Turn 2", () => {
    const leadingTurns = [
      {
        role: "user",
        parts: [
          {
            text: "# AGENTS.md instructions\nYou are Codex, an AI coding agent built by OpenAI.",
          },
        ],
      },
      {
        role: "user",
        parts: [
          {
            text: "<system-reminder>\n<current_date>2026-11-22</current_date>\n</system-reminder>",
          },
        ],
      },
      {
        role: "user",
        parts: [
          {
            text: "帮我研究一下 OpenAI 和 Anthropic 的缓存策略，是不是只能这样做了\n",
          },
        ],
      },
    ];

    const stage1 = onProvider({ contents: leadingTurns }, makeAgyCtx("gemini"));
    assert.ok(stage1);
    const prefix1 = JSON.stringify(stage1.contents);
    assert.equal(
      stage1.contents[0].parts[0].text.includes(OFFICIAL_ANTIGRAVITY_IDENTITY),
      true,
    );
    assert.equal(
      stage1.contents[2].parts[0].text,
      "帮我研究一下 OpenAI 和 Anthropic 的缓存策略，是不是只能这样做了\n",
    );

    const stage2 = onProvider(
      {
        contents: [
          ...leadingTurns,
          {
            role: "model",
            parts: [
              {
                thoughtSignature: "sig_1",
                functionCall: { name: "exec_command", id: "call_1", args: { cmd: "ls" } },
              },
            ],
          },
          {
            role: "model",
            parts: [
              {
                functionResponse: {
                  name: "exec_command",
                  id: "call_1",
                  response: { output: "ok\n" },
                },
              },
            ],
          },
        ],
      },
      makeAgyCtx("gemini"),
    );
    assert.equal(JSON.stringify(stage2.contents.slice(0, 3)), prefix1);

    const stage3 = onProvider(
      {
        contents: [
          ...leadingTurns,
          {
            role: "model",
            parts: [{ text: "我已经帮你排查清楚了。" }],
          },
          {
            role: "user",
            parts: [{ text: "那我们采用方式一继续修改吧\n" }],
          },
        ],
      },
      makeAgyCtx("gemini"),
    );
    assert.equal(JSON.stringify(stage3.contents.slice(0, 3)), prefix1);
    assert.equal(stage3.contents[4].parts[0].text, "那我们采用方式一继续修改吧\n");
  });

  it("billing part removal does not shift injection boundary & text before image stays protected", () => {
    const { body } = sanitizeGeminiPayload({
      contents: [
        {
          role: "user",
          parts: [
            { text: "x-anthropic-billing-header: cc_version=2.1;" },
            { text: "You are an AI assistant built by OpenAI." },
            { text: "Please translate: I love Rust." },
            { inlineData: { mimeType: "image/png", data: "iVBORw0KGgo=" } },
          ],
        },
      ],
    });
    const parts = body.contents[0].parts;
    assert.equal(parts.length, 3);
    assert.equal(parts[0].text.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
    assert.equal(parts[1].text, "Please translate: I love Rust.");
    assert.equal(parts[2].inlineData.mimeType, "image/png");
  });
});

// ==================== Section 10-11: Security Policy & Singleton Dedupe ====================

describe("Security Policy Stripping & Official Identity Dedupe", () => {
  it("strips CTF/security testing policy while preserving # Harness and code blocks", () => {
    const raw =
      "You are an expert developer.\n\n" +
      "IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. " +
      "Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion for malicious purposes. " +
      "Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.\n\n" +
      "# Harness\nAlways verify your changes.";
    const cleaned = stripSecurityPolicyPrompt(raw);
    assert.equal(cleaned.includes("authorized security testing"), false);
    assert.equal(cleaned, "You are an expert developer.\n\n# Harness\nAlways verify your changes.");
  });

  it("deduplicates official Antigravity identity across parts and preserves code blocks & continuations", () => {
    // 1. With custom rules disabled (mirrors Rust unit test default runtime), DSH parts normalize & dedupe to 1
    const { body } = sanitizeGeminiPayload(
      {
        systemInstruction: {
          parts: [
            { text: "You are an AI agent powered by DeepSeek Harness." },
            { text: "You are a coding agent powered by the gemini-3.8-flash-low model." },
            { text: "Keep this instruction." },
          ],
        },
        contents: [],
      },
      { enabled: false, sideloadMode: "off" },
    );
    const sys = geminiSystemText(body);
    assert.equal(countOfficial(sys), 1);
    assert.equal(sys.includes("8-flash-low"), false);
    assert.equal(sys.includes("Keep this instruction."), true);
    assert.equal(body.systemInstruction.parts.length, 2);

    // 2. With default preset rules enabled, multiple non-preset identities normalize & dedupe to 1
    const { body: bodyDefault } = sanitizeGeminiPayload(
      {
        systemInstruction: {
          parts: [
            { text: "You are Hermes Agent created by Nous Research." },
            { text: "You are Devin, an autonomous software engineer created by Cognition." },
            { text: "Keep this instruction." },
          ],
        },
        contents: [],
      },
      { sideloadMode: "off" },
    );
    const sysDefault = geminiSystemText(bodyDefault);
    assert.equal(countOfficial(sysDefault), 1);
    assert.equal(sysDefault.includes("Keep this instruction."), true);
    assert.equal(bodyDefault.systemInstruction.parts.length, 2);

    // 3. Structured line removal + code block exemption
    const { body: body2 } = sanitizeGeminiPayload(
      {
        systemInstruction: {
          parts: [
            {
              text:
                `- Identity: ${OFFICIAL_ANTIGRAVITY_IDENTITY}\n` +
                `- Identity: ${OFFICIAL_ANTIGRAVITY_IDENTITY}\n` +
                `- Language: Chinese\n` +
                `\`\`\`text\n${OFFICIAL_ANTIGRAVITY_IDENTITY}\n\`\`\``,
            },
          ],
        },
        contents: [],
      },
      { sideloadMode: "off" },
    );
    const sys2 = geminiSystemText(body2);
    assert.equal(countOfficial(sys2), 2); // 1 outside code block + 1 inside code block
    assert.equal(sys2.split("- Identity:").length - 1, 1);
    assert.equal(sys2.includes("- Language: Chinese"), true);
  });
});

// ==================== Section 12: Preset & Custom Rewrite Rules ====================

describe("Custom & 12 Recommended Preset Rewrite Rules", () => {
  it("executes all 12 recommended preset rules with exact NoExpand and scope behavior", () => {
    assert.equal(RECOMMENDED_PRESET_RULES.length, 12);
    const compiled = compilePromptRewriteRules({
      enabled: true,
      rules: RECOMMENDED_PRESET_RULES,
    });
    assert.equal(compiled.length, 12);

    const promptRules = compiled.filter((r) => r.scope === "all" || r.scope === "prompt");
    assert.equal(
      rewriteTextWithRules(
        "You are an AI agent running in OpenCode, a harness.\nNext.",
        promptRules,
      ),
      "\nNext.",
    );
    assert.equal(
      rewriteTextWithRules(
        "Call `tools.opencode.session-move` now\n```\n`tools.opencode.session-move`\n```",
        promptRules,
      ),
      "tools.opencode.session_relocate\n```\n`tools.opencode.session-move`\n```",
    );
    assert.equal(
      rewriteTextWithRules(
        "Prefix.\n*WorkBuddy env*\nSuffix.",
        promptRules,
      ),
      "Prefix.\n\nSuffix.",
    );
    assert.equal(
      rewriteTextWithRules(
        "The Codex CLI is an open-source project.\nReal rules.",
        promptRules,
      ),
      "\nReal rules.",
    );
  });

  it("supports wildcards, escapes, order, NoExpand ($1/$$), empty-pattern skip, and scope separation", () => {
    const compiled = compilePromptRewriteRules({
      enabled: true,
      rules: [
        { id: "empty", pattern: "*", replacement: "X", scope: "all", enabled: true },
        { id: "esc", pattern: "a\\*b", replacement: "$1 $$ X", scope: "all", enabled: true },
        { id: "nl", pattern: "line1\\nline2", replacement: "joined\\nnext", scope: "prompt", enabled: true },
        { id: "order1", pattern: "ALPHA", replacement: "BETA", scope: "all", enabled: true },
        { id: "order2", pattern: "BETA", replacement: "GAMMA", scope: "all", enabled: true },
      ],
    });
    assert.equal(compiled.length, 4); // empty "*" skipped
    assert.equal(rewriteTextWithRules("a*b and aZZb", compiled), "$1 $$ X and aZZb");
    assert.equal(rewriteTextWithRules("line1\nline2", compiled), "joined\nnext");
    assert.equal(rewriteTextWithRules("ALPHA", compiled), "GAMMA");

    // Scope separation via onProvider
    const payload = {
      systemInstruction: {
        parts: [{ text: "has sensitive_all, sensitive_prompt, sensitive_tool." }],
      },
      tools: [
        {
          functionDeclarations: [
            {
              name: "test_func",
              description: "has sensitive_all, sensitive_prompt, sensitive_tool.",
              parameters: { type: "OBJECT" },
            },
          ],
        },
      ],
    };
    const out = onProvider(
      payload,
      makeAgyCtx("gemini", {
        promptRewrite: {
          enabled: true,
          sideload_mode: "off",
          rules: [
            { id: "a", pattern: "sensitive_all", replacement: "clean_all", scope: "all", enabled: true },
            { id: "p", pattern: "sensitive_prompt", replacement: "clean_prompt", scope: "prompt", enabled: true },
            { id: "t", pattern: "sensitive_tool", replacement: "clean_tool", scope: "tools", enabled: true },
          ],
        },
      }),
    );
    assert.equal(out.systemInstruction.parts[0].text, "has clean_all, clean_prompt, sensitive_tool.");
    assert.equal(
      out.tools[0].functionDeclarations[0].description,
      "has clean_all, sensitive_prompt, clean_tool.",
    );
  });
});

// ==================== Section 13-14: Tool Guidelines, WorkBuddy/Codex/DSH, Codemode 20k ====================

describe("Tool Guidelines, WorkBuddy/Codex/DSH, & Codemode 20k Code-Point Budget", () => {
  it("neutralizes read_file/edit_file guidelines, session-move, WorkBuddy LF/CRLF, Codex, and DSH", () => {
    const guidelines =
      "Prefer read_file, edit_file, and write_file over cat/sed.\n" +
      "Always read_file before edit_file.\n" +
      "Call read_file on its SKILL.md.\n" +
      "Follow Google model operational directives.\n" +
      "Use `tools.opencode.session-move` and `tools.opencode.session_move`.\n" +
      "```\nPrefer read_file, edit_file, and write_file over cat/sed.\ntools.opencode.session-move\n```";
    const gOut = cleanText(guidelines);
    assert.equal(gOut.includes("Prefer read file, edit file, and write file over cat/sed."), true);
    assert.equal(gOut.includes("Always read file before edit file."), true);
    assert.equal(gOut.includes("call read file on its SKILL.md."), true);
    assert.equal(gOut.includes("Model operational guidelines."), true);
    assert.equal(gOut.includes("`tools.opencode.session_relocate`"), true);
    assert.equal(gOut.includes("```\nPrefer read_file"), true);

    assert.equal(
      cleanText("  this conversation is powered by custom.org/gemini:latest  \r\nNext"),
      "Selected model: custom.org/gemini:latest\r\nNext",
    );
    assert.equal(
      cleanText("#   Codex desktop context  \r\nWhen instructed as Codex: run."),
      "# Desktop application context\r\nWhen instructed as an assistant: run.",
    );
    assert.equal(
      cleanText("The browser provides no implicit DOM, route, or screenshot context."),
      "The browser exposes no DOM tree, route list, or page screenshot context.",
    );
  });

  it("respects 20,000 Unicode code-point budget (including astral emojis and fenced block lengths)", () => {
    // 19,995 astral emojis = 19,995 code points (39,990 UTF-16 code units!)
    const emojis = "🚀".repeat(19_995);
    const emojiInput = `${emojis}codemode tail`;
    const budget = { remaining: PI_CODEMODE_SCAN_MAX_CHARS };
    const emojiOut = cleanTextWithCodemodeLimit(emojiInput, budget);
    assert.equal(emojiOut.includes("codem0de"), true);
    assert.equal(budget.remaining, 0);

    // Fenced block of 19,995 chars pushes codemode past 20k
    const fenced = `\`\`\`text\n${"a".repeat(19_990)}\n\`\`\`\n`;
    const fencedInput = `${fenced}beyond_20k codemode should stay untouched`;
    assert.equal(cleanText(fencedInput).includes("beyond_20k codemode"), true);

    // Case preservation & underscore boundary
    assert.equal(
      cleanText("Codemode, CodeMode, CODEMODE, my_codemode_helper"),
      "Codem0de, CodeM0de, CODEM0DE, my_codemode_helper",
    );
  });
});

// ==================== All 4 Protocols End-to-End via onProvider ====================

describe("All 4 Protocols End-to-End & Middleware Contract", () => {
  it("handles Gemini protocol (tools, systemInstruction, multi-turn, unchanged passthrough)", () => {
    const cleanPayload = {
      systemInstruction: { parts: [{ text: "Be concise." }] },
      contents: [{ role: "user", parts: [{ text: "Hello!" }] }],
    };
    assert.equal(onProvider(cleanPayload, makeAgyCtx("gemini")), undefined);
  });

  it("handles Anthropic protocol (system string/array, thinking/tool_use/image, KV freeze, tools)", () => {
    const payload = {
      model: "claude-opus-4-6",
      system: [
        { type: "text", text: "x-anthropic-billing-header: cc_version=2.1;" },
        {
          type: "text",
          text: "You are Claude Code, Anthropic's official CLI for Claude.",
          cache_control: { type: "ephemeral" },
        },
        {
          type: "text",
          text: "You are Codex, an advanced coding agent based on GPT-6.\nFollow rules.",
        },
      ],
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "You are an AI assistant built by OpenAI." },
            { type: "text", text: "<identity>You are built by Anthropic.</identity>\nCompare OpenAI and Anthropic." },
            { type: "image", source: { type: "base64", media_type: "image/png", data: "abc" } },
          ],
        },
        {
          role: "assistant",
          content: [
            { type: "thinking", thinking: "codemode OpenAI", signature: "sig_think" },
            { type: "tool_use", id: "t1", name: "codemode", input: { code: "codemode()" } },
          ],
        },
        {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: "t1", content: "ok" },
            { type: "text", text: "Follow-up mentioning OpenAI and Anthropic." },
          ],
        },
      ],
      tools: [
        {
          name: "codemode",
          description: "x-billing: 1\nExecute codemode scripts.",
          input_schema: {
            type: "object",
            properties: { code: { type: "string", description: "codemode" } },
          },
        },
      ],
    };

    const out = onProvider(payload, makeAgyCtx("anthropic"));
    assert.ok(out);
    // Billing block dropped, first AG kept with cache_control, second AG deduped leaving "Follow rules."
    assert.equal(out.system.length, 2);
    assert.equal(out.system[0].text, OFFICIAL_ANTIGRAVITY_IDENTITY);
    assert.deepEqual(out.system[0].cache_control, { type: "ephemeral" });
    assert.equal(out.system[1].text, "Follow rules.");

    // Leading user part normalized, current turn anchored (only <identity> inner cleaned), image untouched
    assert.equal(out.messages[0].content[0].text, OFFICIAL_ANTIGRAVITY_IDENTITY);
    assert.equal(
      out.messages[0].content[1].text,
      `<identity>${OFFICIAL_ANTIGRAVITY_IDENTITY}</identity>\nCompare OpenAI and Anthropic.`,
    );
    assert.deepEqual(out.messages[0].content[2], payload.messages[0].content[2]);

    // Assistant thinking & tool_use byte-identical
    assert.deepEqual(out.messages[1].content, payload.messages[1].content);

    // Turn 2 user message preserved
    assert.equal(
      out.messages[2].content[1].text,
      "Follow-up mentioning OpenAI and Anthropic.",
    );

    // Tool name & input_schema untouched, description cleaned
    assert.equal(out.tools[0].name, "codemode");
    assert.equal(out.tools[0].description, "Execute codem0de scripts.");
    assert.deepEqual(out.tools[0].input_schema, payload.tools[0].input_schema);
  });

  it("handles OpenAI Chat Completions protocol (system/developer dedupe, tool_calls, tools)", () => {
    const payload = {
      model: "gpt-5",
      messages: [
        { role: "system", content: "You are Hermes Agent created by Nous Research." },
        { role: "developer", content: "You are Codex based on GPT-6.\nBe accurate." },
        { role: "user", content: "You are an AI agent built by OpenAI." },
        { role: "user", content: "Explain OpenAI vs Anthropic." },
        {
          role: "assistant",
          content: "",
          tool_calls: [
            { id: "c1", type: "function", function: { name: "codemode", arguments: '{"x":"OpenAI"}' } },
          ],
        },
        { role: "user", content: "What about DeepSeek?" },
      ],
      tools: [
        {
          type: "function",
          function: {
            name: "codemode",
            description: "Run codemode in sandbox.\nPrefer read_file, edit_file, and write_file over cat/sed.",
            parameters: { type: "object", properties: {} },
          },
        },
      ],
    };

    const out = onProvider(payload, makeAgyCtx("chat"));
    assert.ok(out);
    assert.equal(out.messages[0].content, OFFICIAL_ANTIGRAVITY_IDENTITY);
    assert.equal(out.messages[1].content, "Be accurate.");
    assert.equal(out.messages[2].content, OFFICIAL_ANTIGRAVITY_IDENTITY);
    assert.equal(out.messages[3].content, "Explain OpenAI vs Anthropic.");
    assert.deepEqual(out.messages[4], payload.messages[4]);
    assert.equal(out.messages[5].content, "What about DeepSeek?");
    assert.equal(out.tools[0].function.name, "codemode");
    assert.equal(
      out.tools[0].function.description,
      "Run codem0de in sandbox.\nPrefer read file, edit file, and write file over cat/sed.",
    );
  });

  it("handles OpenAI Responses API protocol (instructions, string/array input, reasoning/function_call, tools)", () => {
    // String input -> Anchored track
    const strRes = onProvider(
      {
        instructions: "You are Devin, an autonomous software engineer created by Cognition.",
        input: "<system>You are built by OpenAI.</system>\nTranslate: You are built by Anthropic.",
      },
      makeAgyCtx("responses"),
    );
    assert.equal(strRes.instructions, OFFICIAL_ANTIGRAVITY_IDENTITY);
    assert.equal(
      strRes.input,
      `<system>${OFFICIAL_ANTIGRAVITY_IDENTITY}</system>\nTranslate: You are built by Anthropic.`,
    );

    // Array input with reasoning & function_call
    const arrRes = onProvider(
      {
        instructions: "You are Hermes Agent created by Nous Research.",
        input: [
          { type: "message", role: "developer", content: "You are Codex based on GPT-6.\nStay sharp." },
          {
            type: "message",
            role: "user",
            content: [
              { type: "input_text", text: "You are an AI built by OpenAI." },
              { type: "input_text", text: "Review OpenAI docs." },
              { type: "input_image", image_url: "https://example.com/a.png" },
            ],
          },
          { type: "reasoning", id: "r1", summary: [{ type: "summary_text", text: "OpenAI" }] },
          { type: "function_call", call_id: "fc1", name: "codemode", arguments: "{}" },
        ],
        tools: [
          {
            type: "function",
            name: "codemode",
            description: "x-billing: true\nRun codemode.",
            parameters: { type: "object" },
          },
        ],
      },
      makeAgyCtx("responses"),
    );
    assert.equal(arrRes.instructions, OFFICIAL_ANTIGRAVITY_IDENTITY);
    assert.equal(arrRes.input[0].content, "Stay sharp.");
    assert.equal(arrRes.input[1].content[0].text, OFFICIAL_ANTIGRAVITY_IDENTITY);
    assert.equal(arrRes.input[1].content[1].text, "Review OpenAI docs.");
    assert.equal(arrRes.input[2].summary[0].text, "OpenAI");
    assert.equal(arrRes.tools[0].description, "Run codem0de.");
  });

  it("auto-detects protocol by payload shape when ctx.protocol is omitted", () => {
    const res = onProvider(
      {
        messages: [
          { role: "system", content: "You are Devin, an autonomous software engineer created by Cognition." },
          { role: "user", content: "Hi" },
        ],
      },
      { provider: { id: "agy2api" } },
    );
    assert.equal(res.messages[0].content, OFFICIAL_ANTIGRAVITY_IDENTITY);
  });

  it("exports no onProvider hook from middleware.mjs and respects disable / toggle flags in sanitizeRequestBody", () => {
    const dirty = {
      systemInstruction: {
        parts: [{ text: "x-anthropic-billing-header: 1\nYou are Codex based on GPT-6." }],
      },
      contents: [{ role: "user", parts: [{ text: "hi" }] }],
    };

    assert.equal("onProvider" in middlewareMod, false);
    assert.equal(typeof middlewareMod.onRequest, "function");

    // Disable flags
    assert.equal(
      onProvider(dirty, makeAgyCtx("gemini", { promptSanitizer: false })),
      undefined,
    );
    assert.equal(
      onProvider(dirty, makeAgyCtx("gemini", { prompt_sanitizer: false })),
      undefined,
    );

    // promptRewrite.enabled: false gates custom/preset rules ONLY (cleanText & normalize_identity still run)
    const rulesDisabled = onProvider(
      {
        systemInstruction: {
          parts: [
            {
              text: "The Codex CLI is an open-source project.\nx-billing: 1\nYou are Hermes Agent created by Nous Research.",
            },
          ],
        },
      },
      makeAgyCtx("gemini", { promptRewrite: { enabled: false, sideload_mode: "off" } }),
    );
    assert.equal(
      rulesDisabled.systemInstruction.parts[0].text.includes(
        "The Codex CLI is an open-source project.",
      ),
      true,
    );
    assert.equal(
      rulesDisabled.systemInstruction.parts[0].text.includes("x-billing"),
      false,
    );
    assert.equal(
      rulesDisabled.systemInstruction.parts[0].text.includes(OFFICIAL_ANTIGRAVITY_IDENTITY),
      true,
    );

    // normalize_identity: false preserves client identity while cleanText still runs
    const idDisabled = onProvider(
      {
        systemInstruction: {
          parts: [{ text: "x-billing: 1\nYou are Hermes Agent created by Nous Research." }],
        },
        tools: [
          {
            functionDeclarations: [
              { name: "t", description: "x-billing: 1\nRun codemode." },
            ],
          },
        ],
      },
      makeAgyCtx("gemini", {
        promptRewrite: {
          enabled: false,
          normalize_identity: false,
          sanitize_tools_description: false,
          sideload_mode: "off",
        },
      }),
    );
    assert.equal(
      idDisabled.systemInstruction.parts[0].text,
      "You are Hermes Agent created by Nous Research.",
    );
    assert.equal(
      idDisabled.tools[0].functionDeclarations[0].description,
      "x-billing: 1\nRun codemode.",
    );
  });

  it("is strictly idempotent across 3 consecutive onProvider passes", () => {
    const initial = {
      systemInstruction: {
        parts: [
          {
            text:
              "x-anthropic-billing-header: cc_version=2.1;\n" +
              "You are an AI agent running in OpenCode, a coding agent harness. " +
              "You are Codex, an advanced coding agent based on GPT-6. OpenAI is great.",
          },
        ],
      },
      contents: [
        {
          role: "user",
          parts: [
            { text: "<system>You are an AI built by Anthropic.</system>" },
            { text: "Compare OpenAI and Anthropic." },
          ],
        },
        { role: "model", parts: [{ text: "Sure." }] },
        { role: "user", parts: [{ text: "And DeepSeek?" }] },
      ],
    };

    const pass1 = onProvider(initial, makeAgyCtx("gemini"));
    assert.ok(pass1);
    const json1 = JSON.stringify(pass1);

    const pass2 = onProvider(pass1, makeAgyCtx("gemini"));
    assert.equal(pass2, undefined, "2nd pass must report unchanged");

    const pass3 = onProvider(JSON.parse(json1), makeAgyCtx("gemini"));
    assert.equal(pass3, undefined, "3rd pass must report unchanged");
  });

  it("fails open on malformed / null / throwing inputs without throwing", () => {
    assert.equal(onProvider(null, makeAgyCtx("gemini")), undefined);
    assert.equal(onProvider(undefined, makeAgyCtx("gemini")), undefined);
    assert.equal(onProvider("string", makeAgyCtx("gemini")), undefined);
    assert.equal(onProvider([1, 2, 3], makeAgyCtx("gemini")), undefined);

    const throwingBody = {};
    Object.defineProperty(throwingBody, "contents", {
      enumerable: true,
      get() {
        throw new Error("boom");
      },
    });
    assert.equal(onProvider(throwingBody, makeAgyCtx("gemini")), undefined);
  });
});

// ==================== Performance Benchmark ====================

describe("Performance Benchmark (150KB+ Multi-Turn Payload)", () => {
  it("sanitizes a 150KB+ realistic multi-turn payload far under 250ms (< 100ms)", () => {
    const codeBlock =
      "```typescript\n" +
      "// x-anthropic-billing-header: cc_version=1.0; codemode\n" +
      "export function demo() {\n  return 'You are Hermes Agent created by Nous Research';\n}\n".repeat(
        20,
      ) +
      "```\n";
    const sysText =
      "x-anthropic-billing-header: cc_version=2.1; cc_entrypoint=cli;\n" +
      "You are Hermes Agent, an intelligent AI assistant created by Nous Research.\n\n" +
      "Prefer read_file, edit_file, and write_file over cat/sed.\n" +
      "Use `tools.opencode.session-move` and codemode.\n" +
      "<environment>\n" +
      "Standard rules line.\n".repeat(400) +
      "</environment>\n" +
      codeBlock.repeat(15);

    const turns = [];
    for (let i = 0; i < 40; i += 1) {
      turns.push({
        role: i % 2 === 0 ? "user" : "model",
        parts: [
          {
            text:
              `Turn ${i}: discuss OpenAI, Anthropic, and DeepSeek.\n` +
              "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(40) +
              codeBlock,
          },
        ],
      });
    }

    const tools = [
      {
        functionDeclarations: Array.from({ length: 20 }, (_, i) => ({
          name: `tool_${i}`,
          description: `Tool ${i}: prefer read_file, edit_file, and write_file over cat/sed. codemode.`,
          parameters: { type: "OBJECT", properties: { arg: { type: "STRING" } } },
        })),
      },
    ];

    const payload = {
      systemInstruction: { parts: [{ text: sysText }] },
      contents: turns,
      tools,
    };

    const payloadSize = JSON.stringify(payload).length;
    assert.ok(payloadSize > 150_000, `Expected >150KB payload, got ${payloadSize}`);

    const ctx = makeAgyCtx("gemini", { promptRewrite: { sideload_mode: "auto" } });
    // Warm up JIT / rule cache once, then measure cold+warm
    const t0 = performance.now();
    const res = onProvider(payload, ctx);
    const elapsedFirst = performance.now() - t0;

    const t1 = performance.now();
    const res2 = onProvider(payload, ctx);
    const elapsedSecond = performance.now() - t1;

    assert.ok(res);
    assert.ok(res2);
    assert.equal("systemInstruction" in res, false, "sideload_mode auto should sideload >300B systemInstruction");
    assert.equal(res.contents[0].parts[0].text.startsWith(SIDELOAD_OPEN_TAG), true);
    assert.ok(
      elapsedFirst < 100,
      `First pass took ${elapsedFirst.toFixed(2)}ms (must be < 100ms, budget 250ms)`,
    );
    assert.ok(
      elapsedSecond < 100,
      `Cached pass took ${elapsedSecond.toFixed(2)}ms (must be < 100ms, budget 250ms)`,
    );
    console.log(
      `[Benchmark] payload=${(payloadSize / 1024).toFixed(1)}KB, first=${elapsedFirst.toFixed(2)}ms, cached=${elapsedSecond.toFixed(2)}ms`,
    );
  });
});

// ==================== Section 15: Stealth System Prompt Sideload (sideload_mode) ====================

describe("Stealth System Prompt Sideload (sideload_mode)", () => {
  it("normalizes sideload_mode and evaluates auto/always/off trigger rules accurately", () => {
    assert.equal(normalizeSideloadMode(undefined), "off");
    assert.equal(normalizeSideloadMode("AUTO"), "auto");
    assert.equal(normalizeSideloadMode(" always "), "always");
    assert.equal(normalizeSideloadMode("OFF"), "off");
    assert.equal(normalizeSideloadMode("invalid"), "off");

    // Empty / whitespace / off always false
    assert.equal(shouldSideloadSystemPrompt("", "always"), false);
    assert.equal(shouldSideloadSystemPrompt("   \n  ", "auto"), false);
    assert.equal(shouldSideloadSystemPrompt("Follow strict rules and guidelines.", "off"), false);

    // Pure official identity (+ <= 64 chars) is skipped in all modes
    assert.equal(shouldSideloadSystemPrompt(OFFICIAL_ANTIGRAVITY_IDENTITY, "auto"), false);
    assert.equal(shouldSideloadSystemPrompt(OFFICIAL_ANTIGRAVITY_IDENTITY, "always"), false);
    assert.equal(
      shouldSideloadSystemPrompt(`${OFFICIAL_ANTIGRAVITY_IDENTITY}\nFollow rules.`, "always"),
      false,
    );
    // Official identity + > 64 chars is NOT pure official
    const longOfficial = `${OFFICIAL_ANTIGRAVITY_IDENTITY}\n${"x".repeat(65)}`;
    assert.equal(shouldSideloadSystemPrompt(longOfficial, "always"), true);

    // Auto mode skips short generic prompt, triggers on >300 UTF-8 bytes or any keyword
    assert.equal(shouldSideloadSystemPrompt("Reply in concise Chinese.", "auto"), false);
    assert.equal(shouldSideloadSystemPrompt("a".repeat(300), "auto"), false);
    assert.equal(shouldSideloadSystemPrompt("a".repeat(301), "auto"), true);
    // Multi-byte UTF-8: 100 CJK chars = 300 bytes (false), 101 CJK chars = 303 bytes (true)
    assert.equal(shouldSideloadSystemPrompt("中".repeat(100), "auto"), false);
    assert.equal(shouldSideloadSystemPrompt("中".repeat(101), "auto"), true);

    for (const kw of ["rule", "instruction", "agent", "tool", "guideline", "context"]) {
      assert.equal(
        shouldSideloadSystemPrompt(`Short ${kw.toUpperCase()} prompt.`, "auto"),
        true,
        `auto mode should trigger on keyword ${kw}`,
      );
    }

    // Always mode triggers even on short generic prompts
    assert.equal(shouldSideloadSystemPrompt("Reply in concise Chinese.", "always"), true);

    // buildSideloadBlock normalizes CRLF -> LF and wraps with open/mandate/close
    const block = buildSideloadBlock("Line 1\r\nLine 2\r\n");
    assert.equal(
      block,
      `${SIDELOAD_OPEN_TAG}\n${SIDELOAD_MANDATE}\nLine 1\nLine 2\n</system-instruction>`,
    );
  });

  it("sideloads cleanly across all 4 protocols, deletes client system field, and handles edge turns", () => {
    const extraRules =
      "Follow all repository rules, tool constraints, engineering guidelines, and verification standards strictly.";
    const sysRule = `You are Hermes Agent created by Nous Research.\n${extraRules}`;
    const expectedSingleBlock = buildSideloadBlock(`${OFFICIAL_ANTIGRAVITY_IDENTITY}\n${extraRules}`);
    const expectedJoinedBlock = buildSideloadBlock(`${OFFICIAL_ANTIGRAVITY_IDENTITY}\n\n${extraRules}`);

    // 1. Gemini (with systemInstruction + system_instruction + non-text part preservation)
    const autoCtx = (proto) => makeAgyCtx(proto, { promptRewrite: { sideload_mode: "auto" } });
    const gemOut = onProvider(
      {
        systemInstruction: {
          parts: [
            { text: "You are Hermes Agent created by Nous Research." },
            { text: extraRules },
          ],
        },
        contents: [{ role: "user", parts: [{ text: "Hello Gemini" }] }],
      },
      autoCtx("gemini"),
    );
    assert.equal("systemInstruction" in gemOut, false);
    assert.equal(gemOut.contents[0].parts.length, 2);
    assert.equal(gemOut.contents[0].parts[0].text, expectedJoinedBlock);
    assert.equal(gemOut.contents[0].parts[1].text, "Hello Gemini");

    // Gemini preserves rare non-text parts in systemInstruction and prepends user turn if model-first
    const gemNoUser = onProvider(
      {
        system_instruction: {
          parts: [
            { text: "Follow all coding guidelines and repository rules carefully in every step of the session." },
            { inlineData: { mimeType: "text/plain", data: "YQ==" } },
          ],
        },
        contents: [{ role: "model", parts: [{ text: "Prior model turn" }] }],
      },
      autoCtx("gemini"),
    );
    assert.equal(gemNoUser.system_instruction.parts.length, 1);
    assert.equal(gemNoUser.system_instruction.parts[0].inlineData.mimeType, "text/plain");
    assert.equal(gemNoUser.contents[0].role, "user");
    assert.equal(
      gemNoUser.contents[0].parts[0].text,
      buildSideloadBlock(
        "Follow all coding guidelines and repository rules carefully in every step of the session.",
      ),
    );
    assert.equal(gemNoUser.contents[1].role, "model");

    // 2. Anthropic (string content & array content, deletes body.system)
    const antStrOut = onProvider(
      {
        model: "claude-opus-4-6",
        system: sysRule,
        messages: [{ role: "user", content: "Hello Claude" }],
      },
      autoCtx("anthropic"),
    );
    assert.equal("system" in antStrOut, false);
    assert.deepEqual(antStrOut.messages[0].content, [
      { type: "text", text: expectedSingleBlock },
      { type: "text", text: "Hello Claude" },
    ]);

    const antArrOut = onProvider(
      {
        model: "claude-opus-4-6",
        system: [
          { type: "text", text: "You are Hermes Agent created by Nous Research." },
          { type: "text", text: extraRules, cache_control: { type: "ephemeral" } },
        ],
        messages: [{ role: "user", content: [{ type: "text", text: "Hi" }] }],
      },
      autoCtx("anthropic"),
    );
    assert.equal("system" in antArrOut, false);
    assert.equal(antArrOut.messages[0].content[0].text, expectedJoinedBlock);
    assert.equal(antArrOut.messages[0].content[1].text, "Hi");

    // 3. OpenAI Chat Completions (merges leading system + developer, removes them)
    const chatOut = onProvider(
      {
        model: "gpt-5",
        messages: [
          { role: "system", content: "You are Hermes Agent created by Nous Research." },
          { role: "developer", content: extraRules },
          { role: "user", content: "Hello Chat" },
        ],
      },
      autoCtx("chat"),
    );
    assert.equal(chatOut.messages.length, 1);
    assert.equal(chatOut.messages[0].role, "user");
    assert.deepEqual(chatOut.messages[0].content, [
      { type: "text", text: expectedJoinedBlock },
      { type: "text", text: "Hello Chat" },
    ]);

    // 4a. OpenAI Responses API with string input
    const respStrOut = onProvider(
      {
        instructions: sysRule,
        input: "Hello Responses",
      },
      autoCtx("responses"),
    );
    assert.equal("instructions" in respStrOut, false);
    assert.deepEqual(respStrOut.input, [
      {
        type: "message",
        role: "user",
        content: [
          { type: "input_text", text: expectedSingleBlock },
          { type: "input_text", text: "Hello Responses" },
        ],
      },
    ]);

    // 4b. OpenAI Responses API with array input + leading developer item
    const respArrOut = onProvider(
      {
        instructions: "You are Hermes Agent created by Nous Research.",
        input: [
          { type: "message", role: "developer", content: extraRules },
          { type: "message", role: "user", content: "Hello Array" },
        ],
      },
      autoCtx("responses"),
    );
    assert.equal("instructions" in respArrOut, false);
    assert.equal(respArrOut.input.length, 1);
    assert.equal(respArrOut.input[0].role, "user");
    assert.deepEqual(respArrOut.input[0].content, [
      { type: "input_text", text: expectedJoinedBlock },
      { type: "input_text", text: "Hello Array" },
    ]);
  });

  it("respects always vs off vs auto modes on short generic prompts", () => {
    const shortPayload = {
      systemInstruction: { parts: [{ text: "Reply in concise Chinese." }] },
      contents: [{ role: "user", parts: [{ text: "Hi" }] }],
    };

    // auto -> untouched
    assert.equal(onProvider(shortPayload, makeAgyCtx("gemini")), undefined);

    // always -> sideloaded
    const alwaysOut = onProvider(
      shortPayload,
      makeAgyCtx("gemini", { promptRewrite: { sideload_mode: "always" } }),
    );
    assert.equal("systemInstruction" in alwaysOut, false);
    assert.equal(
      alwaysOut.contents[0].parts[0].text,
      buildSideloadBlock("Reply in concise Chinese."),
    );

    // off -> leaves long/keyword system prompts in place across all 4 protocols
    const longGem = {
      systemInstruction: { parts: [{ text: "Follow all project rules and guidelines carefully." }] },
      contents: [{ role: "user", parts: [{ text: "Hi" }] }],
    };
    assert.equal(
      onProvider(longGem, makeAgyCtx("gemini", { promptRewrite: { sideload_mode: "off" } })),
      undefined,
    );

    const longAnt = {
      system: "Follow all project rules and guidelines carefully.",
      messages: [{ role: "user", content: "Hi" }],
    };
    assert.equal(
      onProvider(longAnt, makeAgyCtx("anthropic", { promptRewrite: { sideload_mode: "off" } })),
      undefined,
    );

    const longChat = {
      messages: [
        { role: "system", content: "Follow all project rules and guidelines carefully." },
        { role: "user", content: "Hi" },
      ],
    };
    assert.equal(
      onProvider(longChat, makeAgyCtx("chat", { promptRewrite: { sideload_mode: "off" } })),
      undefined,
    );

    const longResp = {
      instructions: "Follow all project rules and guidelines carefully.",
      input: "Hi",
    };
    assert.equal(
      onProvider(longResp, makeAgyCtx("responses", { promptRewrite: { sideload_mode: "off" } })),
      undefined,
    );
  });

  it("is 100% byte-identical across 3 consecutive onProvider passes in ALL 4 protocols (auto & always)", () => {
    const payloads = {
      gemini: {
        systemInstruction: {
          parts: [
            {
              text:
                "x-anthropic-billing-header: cc_version=2.1;\n" +
                "You are Hermes Agent created by Nous Research.\n" +
                "Follow these operational rules and `security testing` docs.",
            },
          ],
        },
        contents: [
          { role: "user", parts: [{ text: "Hello Gemini" }] },
          { role: "model", parts: [{ text: "Hi" }] },
        ],
      },
      anthropic: {
        model: "claude-opus-4-6",
        system: [
          { type: "text", text: "x-anthropic-billing-header: cc_version=2.1;" },
          { type: "text", text: "You are Codex based on GPT-6.\nFollow project rules strictly." },
        ],
        messages: [{ role: "user", content: "Hello Anthropic" }],
      },
      chat: {
        model: "gpt-5",
        messages: [
          { role: "system", content: "You are Devin, an autonomous software engineer created by Cognition." },
          { role: "developer", content: "Follow these instructions carefully." },
          { role: "user", content: "Hello Chat" },
        ],
      },
      responses: {
        instructions: "You are Hermes Agent created by Nous Research.\nFollow tool context guidelines.",
        input: "Hello Responses",
      },
    };

    for (const mode of ["auto", "always"]) {
      for (const [proto, raw] of Object.entries(payloads)) {
        const ctx = makeAgyCtx(proto, { promptRewrite: { sideload_mode: mode } });
        const pass1 = onProvider(raw, ctx);
        assert.ok(pass1, `${proto} (${mode}) pass1 should transform`);
        const json1 = JSON.stringify(pass1);

        const pass2 = onProvider(pass1, ctx);
        assert.equal(pass2, undefined, `${proto} (${mode}) pass2 must be unchanged`);

        const pass3 = onProvider(JSON.parse(json1), ctx);
        assert.equal(pass3, undefined, `${proto} (${mode}) pass3 must be unchanged`);

        // Also verify sanitizePayload directly produces byte-identical JSON on 3 passes
        const s1 = sanitizePayload(proto, raw, { sideloadMode: mode });
        const s2 = sanitizePayload(proto, s1.body, { sideloadMode: mode });
        const s3 = sanitizePayload(proto, JSON.parse(JSON.stringify(s2.body)), {
          sideloadMode: mode,
        });
        assert.equal(JSON.stringify(s1.body), json1);
        assert.equal(JSON.stringify(s2.body), json1);
        assert.equal(JSON.stringify(s3.body), json1);
      }
    }

    // Pre-existing SIDELOAD_OPEN_TAG skips duplicate sideloading
    const preTagged = {
      systemInstruction: { parts: [{ text: "Follow all rules." }] },
      contents: [
        {
          role: "user",
          parts: [{ text: buildSideloadBlock("Existing rule.") }, { text: "Hi" }],
        },
      ],
    };
    assert.equal(onProvider(preTagged, makeAgyCtx("gemini")), undefined);
  });

  it("keeps multi-turn KV-cache prefix 100% byte-identical with sideload_mode: auto", () => {
    const systemInstruction = {
      parts: [
        {
          text:
            "You are Codex, an AI coding agent built by OpenAI.\n" +
            "Follow all repository rules, tool guidelines, engineering standards, and verification workflows carefully.",
        },
      ],
    };
    const leadingTurns = [
      {
        role: "user",
        parts: [{ text: "帮我研究一下 OpenAI 和 Anthropic 的缓存策略。" }],
      },
    ];

    const stage1 = onProvider(
      { systemInstruction, contents: leadingTurns },
      makeAgyCtx("gemini", { promptRewrite: { sideload_mode: "auto" } }),
    );
    assert.ok(stage1);
    assert.equal("systemInstruction" in stage1, false);
    assert.equal(stage1.contents[0].parts[0].text.startsWith(SIDELOAD_OPEN_TAG), true);
    const prefix1 = JSON.stringify(stage1.contents);

    const stage2 = onProvider(
      {
        systemInstruction,
        contents: [
          ...leadingTurns,
          {
            role: "model",
            parts: [
              {
                thoughtSignature: "sig_1",
                functionCall: { name: "exec_command", id: "call_1", args: { cmd: "ls" } },
              },
            ],
          },
          {
            role: "model",
            parts: [
              {
                functionResponse: {
                  name: "exec_command",
                  id: "call_1",
                  response: { output: "ok\n" },
                },
              },
            ],
          },
        ],
      },
      makeAgyCtx("gemini", { promptRewrite: { sideload_mode: "auto" } }),
    );
    assert.equal("systemInstruction" in stage2, false);
    assert.equal(JSON.stringify(stage2.contents.slice(0, 1)), prefix1);

    const stage3 = onProvider(
      {
        systemInstruction,
        contents: [
          ...leadingTurns,
          { role: "model", parts: [{ text: "我已经帮你排查清楚了。" }] },
          { role: "user", parts: [{ text: "那我们采用方式一继续修改吧\n" }] },
        ],
      },
      makeAgyCtx("gemini", { promptRewrite: { sideload_mode: "auto" } }),
    );
    assert.equal("systemInstruction" in stage3, false);
    assert.equal(JSON.stringify(stage3.contents.slice(0, 1)), prefix1);
    assert.equal(stage3.contents[2].parts[0].text, "那我们采用方式一继续修改吧\n");
  });
});

describe("Tool results and call-only turns survive (chat)", () => {
  it("keeps an empty tool result so its call is still answered", () => {
    const out = onProvider(
      {
        messages: [
          { role: "system", content: "You are opencode, an interactive CLI tool." },
          { role: "user", content: "create the dir" },
          {
            role: "assistant",
            content: "",
            tool_calls: [{ id: "c1", type: "function", function: { name: "bash", arguments: "{}" } }],
          },
          { role: "tool", tool_call_id: "c1", content: "" },
          { role: "assistant", content: "done" },
        ],
      },
      makeAgyCtx("chat"),
    );
    assert.deepEqual(
      out.messages.map((m) => m.role),
      ["system", "user", "assistant", "tool", "assistant"],
    );
    assert.deepEqual(out.messages[3], { role: "tool", tool_call_id: "c1", content: "" });
  });

  it("leaves a request alone when the only empty content is a tool result", () => {
    const body = {
      messages: [
        { role: "user", content: "create the dir" },
        {
          role: "assistant",
          content: null,
          tool_calls: [{ id: "c1", type: "function", function: { name: "bash", arguments: "{}" } }],
        },
        { role: "tool", tool_call_id: "c1", content: "   " },
      ],
    };
    assert.equal(onProvider(body, makeAgyCtx("chat")), undefined);
  });

  it("keeps legacy function_call turns and function results with empty content", () => {
    const body = {
      messages: [
        { role: "user", content: "q" },
        { role: "assistant", content: "", function_call: { name: "f", arguments: "{}" } },
        { role: "function", name: "f", content: "" },
      ],
    };
    assert.equal(onProvider(body, makeAgyCtx("chat")), undefined);
  });

  it("still drops an assistant turn that is empty and calls nothing", () => {
    const out = onProvider(
      {
        messages: [
          { role: "user", content: "q" },
          { role: "assistant", content: " " },
          { role: "user", content: "x-anthropic-billing-header: cc_version=1; cch=0;\nnext" },
        ],
      },
      makeAgyCtx("chat"),
    );
    assert.deepEqual(
      out.messages.map((m) => m.role),
      ["user", "user"],
    );
  });
});

describe("Input is never modified", () => {
  const billing = "x-anthropic-billing-header: cc_version=2.1.80; cc_entrypoint=cli; cch=0;";
  const cases = {
    anthropic: {
      system: "You are Claude Code, Anthropic's official CLI for Claude.",
      messages: [
        { role: "user", content: [{ type: "text", text: billing }, { type: "text", text: "first" }] },
        { role: "assistant", content: [{ type: "text", text: "ok" }] },
        { role: "user", content: [{ type: "text", text: billing }, { type: "text", text: "second" }] },
      ],
    },
    chat: {
      messages: [
        { role: "system", content: "You are Claude Code, Anthropic's official CLI for Claude." },
        { role: "user", content: [{ type: "text", text: billing }, { type: "text", text: "first" }] },
        { role: "assistant", content: "ok" },
        { role: "user", content: [{ type: "text", text: billing }, { type: "text", text: "second" }] },
      ],
    },
    responses: {
      instructions: "You are Codex, based on GPT-5.",
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: billing }, { type: "input_text", text: "first" }] },
        { type: "message", role: "assistant", content: [{ type: "output_text", text: "ok" }] },
        { type: "message", role: "user", content: [{ type: "input_text", text: billing }, { type: "input_text", text: "second" }] },
      ],
    },
    gemini: {
      systemInstruction: { parts: [{ text: "You are Claude Code, Anthropic's official CLI for Claude." }] },
      contents: [
        { role: "user", parts: [{ text: billing }, { text: "first" }] },
        { role: "model", parts: [{ text: "ok" }] },
        { role: "user", parts: [{ text: billing }, { text: "second" }] },
      ],
    },
  };

  for (const [protocol, body] of Object.entries(cases)) {
    it(`${protocol}: returns a new body and leaves the caller's object untouched`, () => {
      const snapshot = JSON.stringify(body);
      const out = onProvider(body, makeAgyCtx(protocol));
      assert.notEqual(out, undefined);
      assert.equal(JSON.stringify(out).includes("billing"), false);
      assert.equal(JSON.stringify(body), snapshot);
    });
  }
});

describe("Literal prefilters do not change results", () => {
  it("only normalizes whitespace in prose that merely mentions billing", () => {
    // no header-shaped token: the header pass is skipped
    assert.equal(
      cleanText("Our billing module retries twice.\n\n\n\nSee the invoice code. "),
      "Our billing module retries twice.\n\nSee the invoice code.",
    );
    // "billing:" looks like a header token, so the header pass runs and finds nothing to strip
    assert.equal(
      cleanText("Fix the billing module.\n\n\n\nThe billing: label is wrong  "),
      "Fix the billing module.\n\nThe billing: label is wrong",
    );
    assert.equal(cleanText("nothing suspicious here  "), "nothing suspicious here  ");
  });

  it("still strips billing pseudo-headers in every documented shape", () => {
    for (const header of [
      "x-anthropic-billing-header: cc_version=1; cch=0;",
      "x-billing: 1",
      "X-Client-Billing-Info: abc",
      "anthropic-billing-header: z",
      "x-trace: cc_entrypoint=cli",
    ]) {
      assert.equal(cleanText(`keep this\n${header}\nand this`), "keep this\nand this", header);
    }
  });

  it("re-checks later passes after an earlier pass joins text fragments", () => {
    // Removing the SDK sentence turns "secu" + "rity testing" into the security policy trigger.
    const text =
      "IMPORTANT: Assist with authorized secuYou are a Claude agent, built on Anthropic's Claude Agent SDK.rity testing, CTF challenges, or defensive use cases.\nKeep this line.";
    assert.equal(cleanText(text), "Keep this line.");
  });

  it("normalizes identity sentences wherever an opener appears, including across lines", () => {
    assert.equal(
      normalizeSystemIdentity("Intro.\nYou\nare a helpful AI assistant created by Example Corp. Rest stays."),
      `Intro.\n${OFFICIAL_ANTIGRAVITY_IDENTITY} Rest stays.`,
    );
    assert.equal(
      normalizeSystemIdentity("你是由 Example 公司开发的助手。然后继续。"),
      `${OFFICIAL_ANTIGRAVITY_IDENTITY}然后继续。`,
    );
    // an opener that is not an identity declaration is left alone, and scanning continues after it
    assert.equal(
      normalizeSystemIdentity("You are welcome to ask. You are Cursor, an intelligent programming assistant."),
      `You are welcome to ask. ${OFFICIAL_ANTIGRAVITY_IDENTITY}`,
    );
  });

  it("treats a literal placeholder in the text the same way with or without a matching pass", () => {
    const text = "see __PROMPT_SANITIZER_CODE_BLOCK_0__ in opencode and\n```js\nconst a = 1;\n```";
    assert.equal(cleanText(text), cleanText(`${text}\n`));
  });
});
