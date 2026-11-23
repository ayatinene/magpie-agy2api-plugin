// Parity with the Rust original: the `#[test]` cases of Antigravity-Manager (beta)
// `src-tauri/src/proxy/mappers/prompt_sanitizer.rs`, ported one-to-one (same names, same
// inputs and expectations) and run against `lib/sanitizer.mjs`.
// Source: https://github.com/lbjlaq/Antigravity-Manager (CC BY-NC-SA 4.0).
//
// Not ported: the four text data URL cases and the environment variable case, because
// the JS port has no such feature.
//
// The Rust tests run with an empty rewrite rule table unless a test loads one, so cases
// that do not configure rules pass `{ rules: [] }` here.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CLAUDE_AGENT_SDK_IDENTITY,
  CLAUDE_CODE_CLI_IDENTITY,
  OFFICIAL_ANTIGRAVITY_IDENTITY,
  RECOMMENDED_PRESET_RULES,
  SELF_IDENTITY_BLOCK,
  cleanText,
  compilePromptRewriteRules,
  isBillingMetadata,
  normalizeClientIdentity,
  normalizeSystemIdentity,
  rewriteTextWithRules,
  sanitizeGeminiPayload,
  stripPipelineMarkers,
  stripSecurityPolicyPrompt,
} from "../lib/sanitizer.mjs";

function countOfficialIdentity(text) {
  return text.split("You are Antigravity").length - 1;
}

function systemInstructionTextExact(payload) {
  const parts = payload?.systemInstruction?.parts;
  if (!Array.isArray(parts)) return "";
  const out = [];
  for (const p of parts) {
    if (typeof p?.text === "string") out.push(p.text);
  }
  return out.join("\n");
}

function rewriteConfig(rules) {
  return {
    enabled: true,
    normalizeIdentity: true,
    sideloadMode: "off",
    sanitizeToolsDescription: true,
    rules: rules.map(([pattern, replacement], index) => ({
      id: `test-${index}`,
      pattern,
      replacement,
      scope: "all",
      enabled: true,
    })),
  };
}

function applyRulesForTest(text, rules) {
  const compiled = compilePromptRewriteRules(rewriteConfig(rules));
  return rewriteTextWithRules(text, compiled) ?? text;
}

// Rust default unit-test runtime has empty PROMPT_REWRITE_RUNTIME unless update_prompt_rewrite_config was called.
const RUST_DEFAULT_UNIT_OPTS = { rules: [] };

// 5. L2328
test("test_client_identity_mapping_normalizes_to_official_antigravity", () => {
  assert.equal(
    normalizeClientIdentity(CLAUDE_AGENT_SDK_IDENTITY),
    OFFICIAL_ANTIGRAVITY_IDENTITY,
  );
  assert.equal(
    normalizeClientIdentity(CLAUDE_CODE_CLI_IDENTITY),
    OFFICIAL_ANTIGRAVITY_IDENTITY,
  );
  assert.equal(
    normalizeClientIdentity("You are an expert coder."),
    "You are an expert coder.",
  );
});

// 6. L2345
test("test_strip_pipeline_markers_and_self_identity", () => {
  assert.equal(
    stripPipelineMarkers("Rule A\n--- [SYSTEM_PROMPT_END] ---\nRule B"),
    "Rule A\n\nRule B",
  );
  assert.equal(
    stripPipelineMarkers(`Intro\n${SELF_IDENTITY_BLOCK}\nOutro`),
    "Intro\n\nOutro",
  );
});

// 7. L2359
test("test_billing_metadata_detection_is_model_agnostic", () => {
  assert.equal(
    isBillingMetadata("x-anthropic-billing-header: cc_version=2.1.270.ffc;"),
    true,
  );
  assert.equal(
    isBillingMetadata("x-anthropic-billing-header: a;\nSecond line prompt instruction"),
    false,
  );
  assert.equal(isBillingMetadata("You are an expert coder."), false);
});

// 8. L2373
test("test_billing_metadata_part_is_dropped_and_undefined_cleaned", () => {
  const payload = {
    systemInstruction: {
      parts: [
        { text: "x-anthropic-billing-header: cc_version=2.1.270.ffc;" },
        { text: "You are an expert coder." },
      ],
    },
    generationConfig: { foo: "[undefined]" },
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const parts = body.systemInstruction.parts;
  assert.equal(parts.length, 1);
  assert.equal(parts[0].text, "You are an expert coder.");
  assert.equal(Object.hasOwn(body.generationConfig, "foo"), false);
});

// 9. L2393
test("test_clean_text_multiline_system_prompt_with_billing", () => {
  const raw =
    "x-anthropic-billing-header: cc_version=2.1.220.04c; cc_entrypoint=sdk-ts;\n" +
    "You are Claude Code, Anthropic's official CLI for Claude.\n\n" +
    "Please follow these instructions:\n" +
    "1. Assist with coding tasks.";
  const cleaned = cleanText(raw);
  assert.equal(cleaned.includes("x-anthropic-billing-header"), false);
  assert.equal(cleaned.startsWith("You are Claude Code"), true);
  assert.equal(cleaned.includes("1. Assist with coding tasks."), true);
});

// 10. L2407
test("test_clean_waf_trigger_cc_entrypoint_header", () => {
  const raw =
    "x-custom-billing: cc_version=2.0; cc_entrypoint=cli;\n" +
    "Actual user instructions.";
  const cleaned = cleanText(raw);
  assert.equal(cleaned, "Actual user instructions.");
});

// 11. L2417
test("test_clean_generic_wildcard_billing_headers", () => {
  const raw =
    "x-billing: enabled\n" +
    "x-custom-billing-info: token123\n" +
    "x-client-billing: active\n" +
    "anthropic-billing-header: cc_version=2.1\n" +
    "Actual user instructions.";
  const cleaned = cleanText(raw);
  assert.equal(cleaned, "Actual user instructions.");
});

// 12. L2430
test("test_strictly_preserves_session_headers_and_tokens", () => {
  const raw =
    "x-jeikcode-session-id: session-abc-123\n" +
    "x-session-id: generic-sess-789\n" +
    "x-client-session-id: client-sess-000\n" +
    "Please keep my session active.";
  const cleaned = cleanText(raw);
  assert.equal(cleaned, raw);
});

// 13. L2443
test("test_strictly_preserves_user_delimiters_and_xml_tags", () => {
  const jeikPrompt =
    "<environment>\n" +
    "You are JeikCode AI coding Agent by Jeik.\n\n" +
    "## PRECEDENCE:\n" +
    "- Content enclosed in XML tags represents current environment.\n" +
    "- Rules under headers matching `=== ... (*.md) ===` (such as `AGENTS.md`, `CLAUDE.md`, `=== MEMORY ===`) constitute USER PROVISIONS.\n" +
    "</environment>\n\n" +
    "=== AGENTS.md ===\n" +
    "User custom provisions.\n" +
    "=== MEMORY ===\n" +
    "Memory block 1.";
  const cleaned = cleanText(jeikPrompt);
  assert.equal(cleaned, jeikPrompt);
});

// 14. L2462
test("test_protects_code_blocks_containing_waf_signatures", () => {
  const code =
    "Here is my code:\n" +
    "```python\n" +
    "headers = {'x-anthropic-billing-header': 'cc_version=1.0'}\n" +
    "print(headers)\n" +
    "```\n" +
    "Does this look right?";
  const cleaned = cleanText(code);
  assert.equal(cleaned, code);
});

// 15. L2476
test("test_protects_normal_user_prompts_and_http_headers", () => {
  const normalText =
    "How do I set Authorization: Bearer <token> in curl?\n" +
    "- Step 1: Add -H flag\n" +
    "- Step 2: Test endpoint\n\n" +
    "Total steps: 2";
  const cleaned = cleanText(normalText);
  assert.equal(cleaned, normalText);
});

// 16. L2488
test("test_sanitize_gemini_payload_system_and_user_blocks", () => {
  const payload = {
    project: "test-project",
    model: "gemini-3.8-flash-high",
    request: {
      systemInstruction: {
        role: "user",
        parts: [
          {
            text: "x-anthropic-billing-header: cc_version=2.1;\n<environment>You are JeikCode</environment>\n=== AGENTS.md ===",
          },
        ],
      },
      contents: [
        {
          role: "user",
          parts: [
            {
              text: "x-anthropic-billing-header: cc_entrypoint=cli;\nPlease analyze my data:\n=== MEMORY ===\n- Metric A: 10\n- Metric B: 20",
            },
          ],
        },
        {
          role: "model",
          parts: [{ text: "Model output response." }],
        },
      ],
    },
  };

  const { body, changed } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(changed, true);

  const sysText = body.request.systemInstruction.parts[0].text;
  assert.equal(sysText.includes("x-anthropic-billing-header"), false);
  assert.equal(sysText.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(sysText.includes("<environment>"), true);
  assert.equal(sysText.includes("</environment>"), true);
  assert.equal(sysText.includes("=== AGENTS.md ==="), true);

  const userText = body.request.contents[0].parts[0].text;
  assert.equal(userText.includes("x-anthropic-billing-header"), false);
  assert.equal(userText.includes("=== MEMORY ==="), true);
  assert.equal(userText.includes("- Metric A: 10\n- Metric B: 20"), true);
});

// 17. L2544
test("test_clean_standalone_billing_header_part_purges_empty_part_and_empty_system_instruction", () => {
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
      contents: [
        {
          role: "user",
          parts: [{ text: "Hello world" }],
        },
      ],
    },
  };

  const { body, changed } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(changed, true);
  assert.equal(Object.hasOwn(body.request, "systemInstruction"), false);
  assert.equal(body.request.contents[0].parts[0].text, "Hello world");
});

// 18. L2581
test("test_ensure_thought_block_always_first_after_sanitization", () => {
  const payload = {
    project: "test-project",
    request: {
      contents: [
        {
          role: "model",
          parts: [
            {
              text: "x-anthropic-billing-header: cc_version=2.1.272.255; cc_entrypoint=cli;\nSome commentary.",
            },
            {
              text: "I am thinking deeply about the problem...",
              thought: true,
              thoughtSignature: "valid_hmac_signature_123456",
            },
            {
              text: "Final answer text.",
            },
          ],
        },
      ],
    },
  };

  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const parts = body.request.contents[0].parts;
  assert.equal(parts[0].thought, true);
  assert.equal(parts[0].text, "I am thinking deeply about the problem...");
  assert.equal(parts[0].thoughtSignature, "valid_hmac_signature_123456");
  assert.equal(parts[1].text, "Some commentary.");
  assert.equal(parts[2].text, "Final answer text.");
});

// 19. L2627
test("test_clean_claude_agent_sdk_preamble", () => {
  const raw =
    "You are a Claude agent, built on Anthropic's Claude Agent SDK.\n\n" +
    "You have access to a variety of tools.";
  const cleaned = cleanText(raw);
  assert.equal(cleaned.includes("Claude Agent SDK"), false);
  assert.equal(cleaned, "You have access to a variety of tools.");
});

// 20. L2639
test("test_clean_claude_agent_sdk_cli_identity", () => {
  const raw =
    "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.\n\n" +
    "You have access to a variety of tools.";
  const cleaned = cleanText(raw);
  assert.equal(cleaned.includes("Claude Agent SDK"), false);
  assert.equal(cleaned.includes("Claude Code"), false);
  assert.equal(cleaned, "You have access to a variety of tools.");

  const normalized = normalizeSystemIdentity(raw);
  assert.equal(normalized.startsWith(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(normalized.includes("You have access to a variety of tools."), true);
  assert.equal(normalized.includes("running within the Claude Agent SDK"), false);

  const sdkCliIdentity =
    "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.";
  assert.equal(
    normalizeClientIdentity(sdkCliIdentity),
    OFFICIAL_ANTIGRAVITY_IDENTITY,
  );
});

// 21. L2666
test("test_clean_waf_trigger_cc_extended_attribution_headers", () => {
  const raw1 =
    "x-anthropic-billing-header: cc_workload=interactive; cc_is_subagent=true;\n" +
    "Actual user instructions.";
  assert.equal(cleanText(raw1), "Actual user instructions.");

  const raw2 =
    "x-client-metadata: cc_workload=interactive; cc_is_subagent=true;\n" +
    "Actual user instructions.";
  assert.equal(cleanText(raw2), "Actual user instructions.");

  const raw3 =
    "x-anthropic-billing-header: cc_prev_req=req_0194e4; cc_prompt_id=e7b4478f; cc_turn_origin=auto;\n" +
    "Actual user instructions.";
  assert.equal(cleanText(raw3), "Actual user instructions.");
});

// 22. L2697
test("test_clean_mid_paragraph_billing_header", () => {
  const raw =
    "Intro text x-anthropic-billing-header: cc_version=2.1.278; cc_entrypoint=cli; cch=fa690; and more text";
  const cleaned = cleanText(raw);
  assert.equal(cleaned.includes("x-anthropic-billing-header"), false);
});

// 23. L2707
test("test_normalize_identity_broad_attribution_forms", () => {
  for (const [raw, expected] of [
    [
      "You are Hermes Agent, an intelligent AI assistant created by Nous Research.",
      OFFICIAL_ANTIGRAVITY_IDENTITY,
    ],
    [
      "You are Codex, an advanced coding agent based on GPT-6.",
      OFFICIAL_ANTIGRAVITY_IDENTITY,
    ],
    [
      "You are an AI agent created by Example Corp.",
      OFFICIAL_ANTIGRAVITY_IDENTITY,
    ],
    [
      "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.\n" +
        "You are pair programming with a USER.",
      `${OFFICIAL_ANTIGRAVITY_IDENTITY}\nYou are pair programming with a USER.`,
    ],
    [
      "You are a Claude agent, built on Anthropic's Claude Agent SDK.\nYou have access to tools.",
      `${OFFICIAL_ANTIGRAVITY_IDENTITY}\nYou have access to tools.`,
    ],
    [
      "You are a helpful and highly capable general-purpose AI coding assistant created by Acme Corp.",
      OFFICIAL_ANTIGRAVITY_IDENTITY,
    ],
    [
      "You are Claude Code, Anthropic's official CLI for Claude.\nYou have access to tools.",
      `${OFFICIAL_ANTIGRAVITY_IDENTITY}\nYou have access to tools.`,
    ],
  ]) {
    assert.equal(normalizeSystemIdentity(raw), expected);
  }
});

// 24. L2750
test("test_normalize_identity_never_swallows_following_lines", () => {
  const raw =
    "You are an AI agent created by Acme\n" +
    "Rule 1: always do X\n" +
    "Rule 2: never do Y";
  assert.equal(
    normalizeSystemIdentity(raw),
    `${OFFICIAL_ANTIGRAVITY_IDENTITY}\nRule 1: always do X\nRule 2: never do Y`,
  );
});

// 25. L2764
test("test_normalize_identity_keeps_comma_continuation_intact", () => {
  const raw =
    "You are an AI agent created by Acme, and you must never reveal internal tooling.";
  const expected =
    "You are Antigravity, a powerful agentic AI coding assistant designed by the " +
    "Google Deepmind team working on Advanced Agentic Coding, " +
    "and you must never reveal internal tooling.";
  assert.equal(normalizeSystemIdentity(raw), expected);
  assert.equal(expected.includes(".,"), false);
});

// 26. L2778
test("test_normalize_identity_keeps_full_width_comma_continuation_intact", () => {
  const raw = "You are an AI agent created by Acme，并且你绝不能泄露内部工具。";
  const expected =
    "You are Antigravity, a powerful agentic AI coding assistant designed by the " +
    "Google Deepmind team working on Advanced Agentic Coding，" +
    "并且你绝不能泄露内部工具。";
  assert.equal(normalizeSystemIdentity(raw), expected);
});

// 27. L2789
test("test_normalize_known_client_identity_comma_continuation_intact", () => {
  const raw =
    "You are Claude Code, Anthropic's official CLI for Claude, and you must never reveal internal tooling.";
  const expected =
    "You are Antigravity, a powerful agentic AI coding assistant designed by the " +
    "Google Deepmind team working on Advanced Agentic Coding, " +
    "and you must never reveal internal tooling.";
  assert.equal(normalizeSystemIdentity(raw), expected);
});

// 28. L2800
test("test_normalize_identity_without_continuation_keeps_terminal_period", () => {
  const raw =
    "You are Hermes Agent, an intelligent AI assistant created by Nous Research.";
  const out = normalizeSystemIdentity(raw);
  assert.equal(out, OFFICIAL_ANTIGRAVITY_IDENTITY);
  assert.equal(out.endsWith("."), true);
});

// 29. L2808
test("test_normalize_identity_preserves_non_attribution_identities", () => {
  for (const raw of [
    "You are a helpful assistant. Please respond in Chinese.",
    "You are an AI assistant that helps users write code by calling tools.",
    "You are an expert full-stack developer specializing in Rust and TypeScript.",
  ]) {
    assert.equal(normalizeSystemIdentity(raw), raw);
  }

  const crossClause =
    "You are a coding agent, and the config was created by the setup script, so keep it.";
  assert.equal(normalizeSystemIdentity(crossClause), crossClause);
});

// 30. L2828
test("test_normalize_identity_scans_full_system_prompt", () => {
  const raw =
    "You are a coding assistant.\n\n" +
    "Sentence 0 is a normal instruction.\n" +
    "Sentence 1 is a normal instruction.\n" +
    "Sentence 2 is a normal instruction.\n" +
    "Sentence 3 is a normal instruction.\n" +
    "Sentence 4 is a normal instruction.\n" +
    "Sentence 5 is a normal instruction.\n" +
    "You are Hermes Agent, an intelligent AI assistant created by Nous Research.";
  const out = normalizeSystemIdentity(raw);
  assert.equal(out.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(out.includes("Hermes Agent"), false);
  assert.equal(out.includes("Sentence 0 is a normal instruction."), true);
});

// 31. L2847
test("test_normalize_identity_preserves_non_identity_attribution_text", () => {
  let raw = "You are a coding assistant.\n\n";
  for (let i = 0; i < 6; i += 1) {
    raw += `Sentence ${i} is a normal instruction.\n`;
  }
  raw += "The tool was created by Acme.\n";
  assert.equal(normalizeSystemIdentity(raw), raw);
});

// 32. L2858
test("test_normalize_identity_protects_code_blocks_and_xml_delimiters", () => {
  const code =
    "You are an AI agent created by Acme.\n\n" +
    "Example config:\n" +
    "```\n" +
    "// generated by Hermes Agent created by Nous Research\n" +
    "```";
  const cleaned = normalizeSystemIdentity(code);
  assert.equal(cleaned.startsWith(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(
    cleaned.includes("// generated by Hermes Agent created by Nous Research"),
    true,
  );

  const xml =
    "<environment>\n" +
    "You are Hermes Agent created by Nous Research.\n" +
    "</environment>\n\n" +
    "=== AGENTS.md ===\nUser provisions.";
  assert.equal(
    normalizeSystemIdentity(xml),
    `<environment>\n${OFFICIAL_ANTIGRAVITY_IDENTITY}\n</environment>\n\n=== AGENTS.md ===\nUser provisions.`,
  );
});

// 33. L2885
test("test_sanitize_gemini_payload_identity_scope_is_system_only", () => {
  const payload = {
    project: "test-project",
    request: {
      systemInstruction: {
        role: "user",
        parts: [
          {
            text: "You are Hermes Agent, an intelligent AI assistant created by Nous Research.",
          },
        ],
      },
      contents: [
        {
          role: "user",
          parts: [{ text: "Quote the note created by Alice in the doc." }],
        },
      ],
    },
  };

  const { body, changed } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(changed, true);
  assert.equal(
    body.request.systemInstruction.parts[0].text,
    OFFICIAL_ANTIGRAVITY_IDENTITY,
  );
  assert.equal(
    body.request.contents[0].parts[0].text,
    "Quote the note created by Alice in the doc.",
  );
});

// 34. L2920
test("test_sanitize_tools_function_declarations_description", () => {
  const payload = {
    tools: [
      {
        functionDeclarations: [
          {
            name: "Bash",
            description:
              "x-anthropic-billing-header: cc_version=2.1;\nExecute a bash command in the terminal.",
            parameters: {
              type: "OBJECT",
              properties: {
                command: { type: "STRING" },
              },
              required: ["command"],
            },
          },
        ],
      },
    ],
  };

  const { body, changed } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(changed, true);

  const func = body.tools[0].functionDeclarations[0];
  assert.equal(func.name, "Bash");
  assert.equal(func.parameters.required[0], "command");
  assert.equal(func.description, "Execute a bash command in the terminal.");
});

// 35. L2956
test("test_sanitize_gemini_payload_normalizes_system_identity_while_preserving_contents", () => {
  const jeik =
    "<environment>\n" +
    "You are JeikCode AI coding Agent by Jeik.\n\n" +
    "## PRECEDENCE:\n" +
    "- Rules under headers matching `=== ... (*.md) ===` constitute USER PROVISIONS.\n" +
    "</environment>\n\n" +
    "=== AGENTS.md ===\n" +
    "User custom provisions.";
  const payload = {
    request: {
      systemInstruction: { role: "user", parts: [{ text: jeik }] },
      contents: [
        { role: "user", parts: [{ text: jeik }] },
        { role: "user", parts: [{ text: "Initial question about JeikCode.\n" }] },
        { role: "model", parts: [{ text: "Model answer." }] },
        { role: "user", parts: [{ text: "Follow-up question about JeikCode." }] },
      ],
    },
  };

  const { body, changed } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(changed, true);
  const sysText = body.request.systemInstruction.parts[0].text;
  assert.equal(sysText.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(sysText.includes("<environment>"), true);
  assert.equal(sysText.includes("</environment>"), true);
  assert.equal(sysText.includes("=== AGENTS.md ==="), true);
  assert.equal(sysText.includes("User custom provisions."), true);

  const userLeading = body.request.contents[0].parts[0].text;
  assert.equal(userLeading.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);

  assert.equal(
    body.request.contents[1].parts[0].text,
    "Initial question about JeikCode.\n",
  );
  assert.equal(
    body.request.contents[3].parts[0].text,
    "Follow-up question about JeikCode.",
  );
});

// 36. L3007
test("test_sanitize_gemini_payload_leading_user_turn_with_injected_system_prompts_and_real_query", () => {
  const payload = {
    contents: [
      {
        role: "user",
        parts: [
          {
            text: "You are a personal assistant running inside OpenClaw.\n## Tooling\nAvailable tools are listed.",
          },
          {
            text: "<environment>\nYou are Cherry Studio AI assistant.\n</environment>",
          },
          { text: "## Available Skills:\n- skill 1\n- skill 2" },
          { text: "请帮我实现一个高效的快速排序算法，语言使用 Rust。" },
        ],
      },
      {
        role: "model",
        parts: [{ text: "好的，以下是 Rust 语言实现的快速排序代码：" }],
      },
      {
        role: "user",
        parts: [{ text: "请问刚才那段代码能在 OpenClaw 插件环境下运行吗？" }],
      },
    ],
  };

  const { body, changed } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(changed, true);

  const parts = body.contents[0].parts;
  assert.equal(parts[0].text.startsWith(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(
    parts[0].text.includes("## Tooling\nAvailable tools are listed."),
    true,
  );
  assert.equal(parts[1].text.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(parts[1].text.includes("<environment>"), true);
  assert.equal(parts[1].text.includes("</environment>"), true);
  assert.equal(parts[2].text, "## Available Skills:\n- skill 1\n- skill 2");
  assert.equal(
    parts[3].text,
    "请帮我实现一个高效的快速排序算法，语言使用 Rust。",
  );
  assert.equal(
    body.contents[2].parts[0].text,
    "请问刚才那段代码能在 OpenClaw 插件环境下运行吗？",
  );
});

// 37. L3083
test("test_code_block_with_placeholder_text_no_recursive_expansion", () => {
  const input =
    "Some text before\n" +
    "```rust\n" +
    'let x = "__PROMPT_SANITIZER_CODE_BLOCK_0__";\n' +
    "```\n" +
    "Some text after";
  const cleaned = cleanText(input);
  assert.equal(cleaned.includes("__PROMPT_SANITIZER_CODE_BLOCK_0__"), true);
});

// 38. L3097
test("test_exclamation_mark_instruction_not_swallowed", () => {
  const raw =
    "You are an AI assistant created by Example Corp! " +
    "Please always format all responses as valid JSON only.";
  const normalized = normalizeSystemIdentity(raw);
  assert.equal(
    normalized.includes("Please always format all responses as valid JSON only."),
    true,
  );
});

// 39. L3108
test("test_comprehensive_harness_and_identity_normalization", () => {
  const testCases = [
    [
      "OpenCode生产真实报文",
      "You are opencode, an interactive CLI tool that helps users with software engineering tasks. Use the instructions below and the tools available to you to assist the user.",
      "opencode",
    ],
    [
      "OpenClaw生产真实报文",
      "---\nOpenClaw plugin-injected system context. This block is not workspace file content.\n---\nYou are a personal assistant running inside OpenClaw.\n## Tooling\nAvailable tools are policy-filtered.",
      "running inside OpenClaw",
    ],
    [
      "Claude Code CLI真实报文",
      "You are Claude Code, Anthropic's official CLI for Claude.\nTools available.",
      "Claude Code",
    ],
    [
      "Claude Agent SDK运行时报文",
      "You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.\nTools available.",
      "Claude Agent SDK",
    ],
    [
      "Claude Agent独立身份声明",
      "You are a Claude agent, built on Anthropic's Claude Agent SDK.\nYou have tools.",
      "Claude Agent SDK",
    ],
    [
      "Cursor真实报文",
      "You are an intelligent programming assistant integrated into Cursor editor.",
      "Cursor editor",
    ],
    [
      "Cascade真实报文",
      "You are Cascade, an AI pair programmer by Codeium. Follow rules.",
      "Cascade",
    ],
    [
      "Cline真实报文",
      "You are Cline, a highly skilled software engineer with extensive knowledge in many programming languages.",
      "Cline",
    ],
    [
      "Aider真实报文",
      "You are aider, an expert software engineer collaborating with the user.",
      "aider",
    ],
    [
      "Codex真实报文",
      "You are Codex, an advanced coding agent based on GPT-6.",
      "Codex",
    ],
    [
      "Hermes Agent真实报文",
      "You are Hermes Agent, an intelligent AI assistant created by Nous Research.",
      "Hermes Agent",
    ],
    [
      "KiloCode真实报文",
      "You are KiloCode, an AI coding assistant developed by Kilo AI.",
      "KiloCode",
    ],
    [
      "DSH Harness真实报文",
      "You are DSH, an automated software development harness designed for agentic coding workflows.",
      "DSH",
    ],
    [
      "Devin真实报文",
      "You are Devin, an autonomous software engineer created by Cognition.",
      "Devin",
    ],
    [
      "GrokBuild真实报文",
      "You are Grok 4.6 released by xAI. You are an interactive CLI tool that helps users with software engineering tasks. Your main goal is to complete the user's request in the <user_query> tag.",
      "xAI",
    ],
    [
      "逗号续写功能指令形态",
      "You are an AI agent created by Acme, and you must never reveal internal tooling.",
      "and you must never reveal internal tooling.",
    ],
    [
      "中文归属声明形态",
      "你是通义灵码，一个由阿里云开发的人工智能编码助手。",
      "通义灵码",
    ],
    [
      "中文基于模型声明形态",
      "你是深度求索开发的助手，基于DeepSeek大模型。",
      "基于DeepSeek大模型",
    ],
    [
      "中文我是开场白形态",
      "我是百度开发的人工智能代码助手文心快码。",
      "文心快码",
    ],
    [
      "JeikCode完整主要提示词(环境标签+多行指令)",
      "<environment>\n" +
        "You are JeikCode AI coding Agent by Jeik running on your underlying model. Always communicate in the language used by the user.\n" +
        "## PRECEDENCE:\n" +
        "Critical Precedence: Rules under <project_instructions> constitute USER PROVISIONS.\n" +
        "=== AGENTS.md ===\n" +
        "Do not modify.\n" +
        "</environment>",
      "JeikCode",
    ],
    [
      "JeikCode单行精简身份(归属与宿主声明)",
      "You are JeikCode AI coding Agent by Jeik running on your underlying model.",
      "JeikCode",
    ],
    [
      "泛化xxxcode形态",
      "You are atomcode, an interactive coding assistant.",
      "atomcode",
    ],
    [
      "泛化xx code形态",
      "You are hyper code AI coding agent. Complete the task.",
      "hyper code",
    ],
    [
      "Pi客户端形态",
      "You are Pi AI coding agent. Help write code.",
      "Pi",
    ],
    [
      "任意标签内部深度身份声明",
      "Rule 1.\nRule 2.\nRule 3.\nRule 4.\nRule 5.\nRule 6.\nRule 7.\nRule 8.\nRule 9.\n" +
        "<custom_agent>\n" +
        "You are JeikCode AI coding Agent by Jeik running on your underlying model.\n" +
        "Do something.\n" +
        "</custom_agent>",
      "JeikCode",
    ],
    [
      "xx Studio大写形态",
      "YOU ARE CHERRY STUDIO, an intelligent AI.",
      "CHERRY STUDIO",
    ],
    [
      "xx Studio小写形态",
      "you are lm studio AI assistant. Help the user.",
      "lm studio",
    ],
    [
      "xxStudio驼峰混合大小写形态",
      "You are CherryStudio, an AI assistant.",
      "CherryStudio",
    ],
    [
      "xxStudio全大写形态",
      "YOU ARE LMSTUDIO AI ASSISTANT.",
      "LMSTUDIO",
    ],
    [
      "**claw大写形态",
      "YOU ARE OPENCLAW.",
      "OPENCLAW",
    ],
    [
      "** claw双词小写形态",
      "you are open claw AI coding agent.",
      "open claw",
    ],
    [
      "标签包裹的Cherry Studio大小写不敏感形态",
      "<environment>\nYOU ARE CHERRY STUDIO AI ASSISTANT.\n</environment>",
      "CHERRY STUDIO",
    ],
  ];

  const officialPrefix = OFFICIAL_ANTIGRAVITY_IDENTITY.replace(/\.$/, "");
  for (const [name, raw, keyFragment] of testCases) {
    const out = normalizeSystemIdentity(raw);
    assert.notEqual(out, raw, `Case '${name}' 必须被归一化处理`);
    assert.equal(
      out.includes(officialPrefix),
      true,
      `Case '${name}' 必须包含官方 Antigravity 身份`,
    );
    if (keyFragment !== "and you must never reveal internal tooling.") {
      assert.equal(
        out.toLowerCase().includes(keyFragment.toLowerCase()),
        false,
        `Case '${name}' 不得残留第三方指纹: '${keyFragment}'`,
      );
    } else {
      assert.equal(
        out.includes(keyFragment),
        true,
        `Case '${name}' 必须完整保留逗号续写指令`,
      );
    }
  }
});

// 40. L3310
test("test_strictly_protects_generic_prompts", () => {
  const protectedCases = [
    ["官方Antigravity自身(保持稳定)", OFFICIAL_ANTIGRAVITY_IDENTITY],
    [
      "通用中性提示词(绝对保护)",
      "You are a helpful assistant. Please respond in Chinese.",
    ],
    [
      "通用AI编程提示词(绝对保护)",
      "You are an AI assistant that helps users write code by calling tools.",
    ],
    [
      "WorkBuddy会话动力声明(豁免不洗)",
      "This conversation is powered by gemini-3.8-flash-medium\r\n\r\nYour main goal is to follow the USER's instructions at each message, denoted by the <user_query> tag.",
    ],
    [
      "开发者专家角色设定(绝对保护)",
      "You are an expert full-stack developer specializing in Rust and TypeScript.",
    ],
    [
      "代码块中包含的特征(绝对保护)",
      "You are a helpful assistant.\n```python\n// generated by Hermes Agent created by Nous Research\nheaders = {'x-anthropic-billing-header': 'test'}\n```",
    ],
    [
      "头部扫描窗口之外的引用(绝对保护)",
      "You are a helpful assistant.\nSentence 1.\nSentence 2.\nSentence 3.\nSentence 4.\nSentence 5.\nSentence 6.\nSentence 7.\nSentence 8.\nThe module was created by Acme.",
    ],
  ];

  for (const [name, raw] of protectedCases) {
    const out = normalizeSystemIdentity(raw);
    assert.equal(out, raw, `Case '${name}' 属于保护范畴，绝不可被误杀改写！`);
  }
});

// 41. L3349
test("test_competitor_brands_normalization_to_google", () => {
  const rawEn =
    "Powered by OpenAI and Anthropic, using Qwen architecture under ByteDance, Tencent, Xiaomi and Huawei.";
  const cleanedEn = normalizeSystemIdentity(rawEn);
  assert.equal(cleanedEn.toLowerCase().includes("openai"), false);
  assert.equal(cleanedEn.toLowerCase().includes("anthropic"), false);
  assert.equal(cleanedEn.toLowerCase().includes("qwen"), false);
  assert.equal(cleanedEn.toLowerCase().includes("bytedance"), false);
  assert.equal(cleanedEn.toLowerCase().includes("tencent"), false);
  assert.equal(cleanedEn.toLowerCase().includes("xiaomi"), false);
  assert.equal(cleanedEn.toLowerCase().includes("huawei"), false);
  assert.equal(cleanedEn.includes("Google"), true);

  const rawDecl = "You are powered by DeepSeek, trained by Baidu AI.";
  const cleanedDecl = normalizeSystemIdentity(rawDecl);
  assert.equal(cleanedDecl.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(cleanedDecl.toLowerCase().includes("deepseek"), false);
  assert.equal(cleanedDecl.toLowerCase().includes("baidu"), false);

  const rawComma = "You are Claude Code, powered by DeepSeek.";
  const cleanedComma = normalizeSystemIdentity(rawComma);
  assert.equal(
    cleanedComma.includes(OFFICIAL_ANTIGRAVITY_IDENTITY.replace(/\.$/, "")),
    true,
  );
  assert.equal(cleanedComma.toLowerCase().includes("claude code"), false);
  assert.equal(cleanedComma.toLowerCase().includes("deepseek"), false);
  assert.equal(cleanedComma.includes("Google"), true);

  const rawStructured =
    "- Identity: built by OpenAI, running on DeepSeek model.";
  const cleanedStructured = normalizeSystemIdentity(rawStructured);
  assert.equal(cleanedStructured.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(cleanedStructured.toLowerCase().includes("openai"), false);
  assert.equal(cleanedStructured.toLowerCase().includes("deepseek"), false);

  const rawTail = "Some preamble sentence.\nYou are built on DeepSeek";
  const cleanedTail = normalizeSystemIdentity(rawTail);
  assert.equal(
    cleanedTail.toLowerCase().includes("deepseek"),
    false,
    `尾部无标点身份声明句漏网: ${cleanedTail}`,
  );
  assert.equal(
    cleanedTail.includes("Google") ||
      cleanedTail.includes(OFFICIAL_ANTIGRAVITY_IDENTITY),
    true,
  );

  const rawMemory =
    "# MEMORY\n" +
    "百度 BD-09 坐标系与 Google Web 服务不同，需注意转换。\n" +
    "使用 deepseek-harness 跑批时，Qwen 与华为的模型指标存档在 metrics/ 下。\n" +
    "OpenAI 与 Anthropic 的 API 限流策略见 docs/rate-limits.md。\n";
  const cleanedMemory = normalizeSystemIdentity(rawMemory);
  assert.equal(cleanedMemory, rawMemory, "业务内容区必须逐字保留");

  const rawZh =
    "本项目由字节跳动开发，经由腾讯、小米、华为以及通义千问、百度深度支持。";
  assert.equal(normalizeSystemIdentity(rawZh), rawZh);

  const rawCode =
    "Instructions from OpenAI:\n" +
    "```python\n" +
    "import openai\n" +
    "from anthropic import Anthropic\n" +
    "# Supported by Tencent and Huawei\n" +
    "client = openai.OpenAI()\n" +
    "```\n" +
    "End of instructions.";
  const cleanedCode = normalizeSystemIdentity(rawCode);
  assert.equal(cleanedCode.includes("import openai"), true);
  assert.equal(cleanedCode.includes("from anthropic import Anthropic"), true);
  assert.equal(cleanedCode.includes("# Supported by Tencent and Huawei"), true);
  assert.equal(cleanedCode.includes("client = openai.OpenAI()"), true);
  assert.equal(cleanedCode.includes("Instructions from OpenAI:"), true);
});

// 42. L3433
test("test_issue_3764_current_turn_content_is_never_rewritten", () => {
  for (const original of [
    "请翻译这句话：你是由 Anthropic 开发的助手。",
    "Please translate: You are a helpful assistant created by Anthropic.",
    "你是基于什么模型开发的？",
    "你是由谁开发的？请给出来源。",
    '请校对："You are an AI assistant built by OpenAI."',
    "Compare OpenAI GPT-4o with Anthropic Claude and tell me about ByteDance, Tencent, Baidu.",
  ]) {
    const payload = {
      contents: [{ role: "user", parts: [{ text: original }] }],
    };
    const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
    assert.equal(
      body.contents[0].parts[0].text,
      original,
      `当前轮用户正文被改写: ${original}`,
    );
  }
});

// 43. L3457
test("test_issue_3764_anchor_regions_only_cleaned_in_current_turn", () => {
  const text =
    "<system>You are an AI assistant built by OpenAI.</system>\n\n" +
    "请把下面这句话翻译成英文：I love Rust.";
  const payload = {
    contents: [{ role: "user", parts: [{ text }] }],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const out = body.contents[0].parts[0].text;
  assert.equal(out.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(out.toLowerCase().includes("openai"), false);
  assert.equal(out.includes("<system>"), true);
  assert.equal(out.includes("</system>"), true);
  assert.equal(out.includes("请把下面这句话翻译成英文：I love Rust."), true);

  const text2 =
    "<identity>You are a coding agent by Acme.</identity>\n\n" +
    "<environment>You are a helper created by Anthropic.</environment>\n" +
    "翻译上面的内容。";
  const payload2 = {
    contents: [{ role: "user", parts: [{ text: text2 }] }],
  };
  const { body: body2 } = sanitizeGeminiPayload(payload2, RUST_DEFAULT_UNIT_OPTS);
  const out2 = body2.contents[0].parts[0].text;
  assert.equal(out2.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(
    out2.includes("<environment>You are a helper created by Anthropic.</environment>"),
    true,
  );
  assert.equal(out2.includes("翻译上面的内容。"), true);
});

// 44. L3494
test("test_identity_declaration_never_crosses_newline", () => {
  const system =
    "You are a helpful assistant\n\nBased on the user's input, respond briefly.";
  const payload = {
    systemInstruction: { parts: [{ text: system }] },
    contents: [],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(
    body.systemInstruction.parts[0].text,
    system,
    "身份声明不得跨空行吞掉后续段落",
  );
});

// 45. L3510
test("test_identity_declaration_rejects_cross_clause_bridge", () => {
  for (const original of [
    "You are a coding agent, and the config was created by the setup script, so keep it.",
    "You are a coding agent, and it was created by the setup script, so keep it.",
    "You are a coding agent, but the config was created by the setup script, so keep it.",
  ]) {
    const payload = {
      systemInstruction: { parts: [{ text: original }] },
      contents: [],
    };
    const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
    assert.equal(
      body.systemInstruction.parts[0].text,
      original,
      `跨子句误伤: ${original}`,
    );
  }

  assert.equal(
    normalizeSystemIdentity(
      "You are Hermes Agent, an intelligent AI assistant created by Nous Research.",
    ),
    OFFICIAL_ANTIGRAVITY_IDENTITY,
  );
});

// 46. L3538
test("test_injected_leading_parts_are_system_scoped", () => {
  const payload = {
    contents: [
      {
        role: "user",
        parts: [
          { text: "You are an AI assistant built by OpenAI. Always use tools." },
          { text: "请翻译：I love Rust." },
        ],
      },
    ],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const parts = body.contents[0].parts;
  assert.equal(parts[0].text.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(parts[0].text.includes("OpenAI"), false);
  assert.equal(parts[1].text, "请翻译：I love Rust.");

  const payload2 = {
    contents: [
      {
        role: "user",
        parts: [{ text: "You are an AI assistant built by OpenAI." }],
      },
      {
        role: "user",
        parts: [{ text: "First question about OpenAI.\n" }],
      },
      { role: "model", parts: [{ text: "Understood." }] },
      {
        role: "user",
        parts: [{ text: "Compare OpenAI and Anthropic models." }],
      },
    ],
  };
  const { body: body2 } = sanitizeGeminiPayload(payload2, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(
    body2.contents[0].parts[0].text.includes(OFFICIAL_ANTIGRAVITY_IDENTITY),
    true,
  );
  assert.equal(body2.contents[1].parts[0].text, "First question about OpenAI.\n");
  assert.equal(
    body2.contents[3].parts[0].text,
    "Compare OpenAI and Anthropic models.",
  );
});

// 47. L3585
test("test_text_part_after_image_is_still_protected", () => {
  const payload = {
    contents: [
      {
        role: "user",
        parts: [
          { text: "You are an AI assistant built by OpenAI." },
          { text: "Please translate: I love Rust." },
          { inlineData: { mimeType: "image/png", data: "iVBORw0KGgo=" } },
        ],
      },
    ],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const parts = body.contents[0].parts;
  assert.equal(parts[0].text.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(parts[1].text, "Please translate: I love Rust.");
  assert.notEqual(parts[2].inlineData, undefined);
});

// 48. L3610
test("test_billing_part_removal_does_not_shift_injection_boundary", () => {
  const payload = {
    contents: [
      {
        role: "user",
        parts: [
          { text: "x-anthropic-billing-header: cc_version=2.1;" },
          { text: "You are an AI assistant built by OpenAI." },
          { text: "请翻译：I love Rust." },
        ],
      },
    ],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const parts = body.contents[0].parts;
  assert.equal(parts.length, 2);
  assert.equal(parts[0].text.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(parts[1].text, "请翻译：I love Rust.");
});

// 49. L3636
test("test_sanitize_is_idempotent_across_passes", () => {
  const payload = {
    systemInstruction: {
      parts: [
        {
          text: "You are Codex, an advanced coding agent based on GPT-6. OpenAI is great.",
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
  const { body: b1 } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(
    b1.contents[0].parts[1].text,
    "Compare OpenAI and Anthropic.",
    "首轮用户提问在进入多轮对话后仍必须原样保护，不得被回溯改写",
  );
  const once = JSON.stringify(b1);
  const { body: b2 } = sanitizeGeminiPayload(b1, RUST_DEFAULT_UNIT_OPTS);
  const { body: b3 } = sanitizeGeminiPayload(b2, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(JSON.stringify(b3), once, "清洗必须幂等");
});

// 50. L3664
test("test_multi_turn_transition_freezes_leading_user_prefix_for_kv_cache", () => {
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
          text: "<system-reminder>\n<codex_apps_client_time_context><current_date>2026-11-08</current_date></codex_apps_client_time_context>\n</system-reminder>",
        },
      ],
    },
    {
      role: "user",
      parts: [
        {
          text: "帮我研究一下这个 XUI 的 node 逻辑，对比一下 OpenAI 和 Anthropic 的缓存策略，是不是只能这样做了\n",
        },
      ],
    },
  ];

  const { body: turn1Initial } = sanitizeGeminiPayload(
    { contents: leadingTurns },
    RUST_DEFAULT_UNIT_OPTS,
  );
  const prefixStage1 = turn1Initial.contents;

  assert.equal(
    prefixStage1[0].parts[0].text.includes(OFFICIAL_ANTIGRAVITY_IDENTITY),
    true,
  );
  assert.equal(
    prefixStage1[2].parts[0].text,
    "帮我研究一下这个 XUI 的 node 逻辑，对比一下 OpenAI 和 Anthropic 的缓存策略，是不是只能这样做了\n",
  );

  const { body: turn1ToolLoop } = sanitizeGeminiPayload(
    {
      contents: [
        ...leadingTurns,
        {
          role: "model",
          parts: [
            {
              thoughtSignature: "sig_1",
              functionCall: {
                name: "exec_command",
                id: "call_1",
                args: { cmd: "ls" },
              },
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
    RUST_DEFAULT_UNIT_OPTS,
  );
  const prefixStage2 = turn1ToolLoop.contents.slice(0, 3);
  assert.deepEqual(prefixStage2, prefixStage1);

  const { body: turn2NewUser } = sanitizeGeminiPayload(
    {
      contents: [
        ...leadingTurns,
        {
          role: "model",
          parts: [
            {
              thoughtSignature: "sig_1",
              functionCall: {
                name: "exec_command",
                id: "call_1",
                args: { cmd: "ls" },
              },
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
    RUST_DEFAULT_UNIT_OPTS,
  );
  const turn2Contents = turn2NewUser.contents;
  const prefixStage3 = turn2Contents.slice(0, 3);
  assert.deepEqual(prefixStage3, prefixStage1);
  assert.equal(turn2Contents[6].parts[0].text, "那我们采用方式一继续修改吧\n");
});

// 51. L3767
test("test_strip_security_policy_prompt_with_harness", () => {
  const raw =
    "You are an expert software developer.\n\n" +
    "IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. " +
    "Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion for malicious purposes. " +
    "Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.\n\n" +
    "# Harness\n" +
    "Always verify your changes before committing.";

  const cleaned = stripSecurityPolicyPrompt(raw);
  assert.equal(cleaned.includes("authorized security testing"), false);
  assert.equal(cleaned.includes("defensive use cases"), false);
  assert.equal(cleaned.includes("You are an expert software developer."), true);
  assert.equal(
    cleaned.includes("# Harness\nAlways verify your changes before committing."),
    true,
  );
});

// 52. L3785
test("test_strip_security_policy_prompt_without_harness", () => {
  const raw =
    "System guidance:\n\n" +
    "IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. " +
    "Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion for malicious purposes. " +
    "Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.\n\n" +
    "Please follow standard coding guidelines.";

  const cleaned = stripSecurityPolicyPrompt(raw);
  assert.equal(cleaned.includes("authorized security testing"), false);
  assert.equal(
    cleaned,
    "System guidance:\n\nPlease follow standard coding guidelines.",
  );
});

// 53. L3803
test("test_strip_security_policy_prompt_preserves_code_block", () => {
  const raw =
    "You are an assistant.\n\n" +
    "IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion for malicious purposes. Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.\n\n" +
    "```python\n" +
    "# Code must not be touched:\n" +
    'msg = "IMPORTANT: Assist with authorized security testing... defensive use cases."\n' +
    "```";

  const cleaned = stripSecurityPolicyPrompt(raw);
  assert.equal(cleaned.startsWith("IMPORTANT: Assist with"), false);
  assert.equal(
    cleaned.includes(
      '```python\n# Code must not be touched:\nmsg = "IMPORTANT: Assist with authorized security testing... defensive use cases."\n```',
    ),
    true,
  );
});

// 54. L3819
test("test_strip_security_policy_prompt_without_authorized_prefix", () => {
  const raw =
    "System preamble:\n\n" +
    "IMPORTANT: Assist with security testing, defensive security, CTF challenges, and educational contexts. " +
    "Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion for malicious purposes. " +
    "Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.\n\n" +
    "# Harness\n" +
    "Follow all rules.";

  const cleaned = stripSecurityPolicyPrompt(raw);
  assert.equal(cleaned.includes("security testing"), false);
  assert.equal(cleaned.includes("defensive use cases"), false);
  assert.equal(cleaned, "System preamble:\n\n# Harness\nFollow all rules.");
});

// 55. L3836
test("test_sanitize_gemini_payload_drops_security_policy_standalone_part", () => {
  const payload = {
    systemInstruction: {
      parts: [
        {
          text: "IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion for malicious purposes. Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.",
        },
      ],
    },
    contents: [
      {
        role: "user",
        parts: [{ text: "Hello world!" }],
      },
    ],
  };

  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(Object.hasOwn(body, "systemInstruction"), false);
  assert.equal(body.contents[0].parts[0].text, "Hello world!");
});

// 56. L3862
test("test_sanitize_gemini_payload_drops_security_policy_in_contents_user_turn", () => {
  const payload = {
    contents: [
      {
        role: "user",
        parts: [
          {
            text: "IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion for malicious purposes. Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.\n\n# Harness\nPlease fix the gateway bug.",
          },
        ],
      },
    ],
  };

  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const text = body.contents[0].parts[0].text;
  assert.equal(text.includes("authorized security testing"), false);
  assert.equal(text.includes("DoS attacks"), false);
  assert.equal(text.includes("C2 frameworks"), false);
  assert.equal(text.includes("# Harness"), true);
  assert.equal(text.includes("Please fix the gateway bug."), true);
});

// 57. L3886
test("test_normalize_structured_identity_declarations", () => {
  const cases = [
    [
      "- Identity: JeikCode AI coding Agent, provided by Jeik, running on your underlying model.",
      `- Identity: ${OFFICIAL_ANTIGRAVITY_IDENTITY}`,
    ],
    [
      "* Identity: OpenCode AI assistant, built by Community.",
      `* Identity: ${OFFICIAL_ANTIGRAVITY_IDENTITY}`,
    ],
    [
      "Identity: Claude Code, Anthropic's official CLI for Claude.",
      `Identity: ${OFFICIAL_ANTIGRAVITY_IDENTITY}`,
    ],
    [
      "- Role: Cursor agent integrated into Cursor editor.",
      `- Role: ${OFFICIAL_ANTIGRAVITY_IDENTITY}`,
    ],
    [
      "- 身份：JeikCode AI 编程助手，由 Jeik 提供，运行于底层模型。",
      `- 身份：${OFFICIAL_ANTIGRAVITY_IDENTITY}`,
    ],
  ];

  for (const [raw, expected] of cases) {
    assert.equal(normalizeSystemIdentity(raw), expected);
  }
});

// 58. L3918
test("test_user_reported_new_agent_environment_template", () => {
  const rawEnvironment =
    "<environment>\n" +
    "## Identity & Interaction\n" +
    "- Identity: JeikCode AI coding Agent, provided by Jeik, running on your underlying model.\n" +
    "- Language: Always answer in the language used by the user.\n" +
    "- Model identity: When asked about your model identity, answer based on your actual underlying model code.\n" +
    "- No proactive configuration reads: When the user asks about current tools, MCP, Skills, rules, what we have discussed, or similar, answer directly from the interaction history visible in your current context and from the visible `<available_skills>`, `<mcp_server_instructions>`, `<system_rules>`, `<memory>`, `<user_preferences>`, `<project_instructions>`, etc. Read configuration proactively only when the user explicitly asks to inspect the configured models, query session file records, troubleshoot JeikCode logs, or makes another equally explicit request.\n\n" +
    "## Configuration Directories\n" +
    "- Global configuration, sessions, and logs live under `~/.jeikcode/`; project configuration lives under `./` or `./.jeikcode/`. Do not read configuration proactively unless the user has a clear intent for you to do so.\n" +
    "- Preference and rule files (for example, `AGENTS.md`, `JEIKCODE.md`, `CLAUDE.md`, `rules.md`, `glossary.md`, `dbwords.md`, `memory.md`) take effect immediately upon modification. When the user asks you to change project standards, only scan and modify `./AGENTS.md`.\n\n" +
    "## PRECEDENCE:\n" +
    "- Content inside `<system_rules>`: default system rules.\n" +
    "- Content inside `<user_preferences>` or `<memory>`: global user preferences.\n" +
    "- Content inside `<project_instructions>`: project standards and constraints.\n" +
    "- When the rule sets do not conflict, all three apply simultaneously.\n" +
    "- When they conflict, apply the precedence `project_instructions >> memory > user_preferences > system_rules`.\n" +
    "- When a rule governs normative work directed at others (for example, opinions on others' work, requests, code review, coding standards, or PR review), apply only the public `project_instructions` rules; do not include user personal preferences from `user_preferences`, `memory`, etc. In all other cases, determine the effective scope of each rule by whether the work conflicts.\n" +
    "- Tool invocation precedence: when built-in tools, Skills, and MCP tools can all solve the user's problem, invoke them in this strict order: `Skills > MCP > Built-in Tools > Custom Scripts`.\n\n" +
    "## Runtime Environment\n" +
    "- Platform: Windows 11 Pro (x64, AMD64).\n" +
    "- Project working directory: `E:/code/jeikcode`.\n" +
    "- Git branch: `beta`.\n" +
    '- Command habit: On Windows, use forward slashes "/" in all scenarios, and locate executables with `where`.\n' +
    '- Temp files: use `"$TMPDIR"` instead of hardcoding `/tmp`; it works for shell-internal paths and as an argument to native Windows programs (python / node / curl, etc.); use `"$TMPDIR_WIN"` for nested non-bash shells.\n' +
    '- Desktop: use `"$DESKTOP"` instead of assuming ~/Desktop; it honors a relocated or redirected desktop; `"$DESKTOP_WIN"` is the equivalent alias.\n' +
    "</environment>";

  const payload = {
    systemInstruction: { parts: [{ text: rawEnvironment }] },
    contents: [{ role: "user", parts: [{ text: "Help me write a Python script." }] }],
  };

  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const sysText = body.systemInstruction.parts[0].text;

  assert.equal(sysText.includes(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(sysText.includes(`- Identity: ${OFFICIAL_ANTIGRAVITY_IDENTITY}`), true);
  assert.equal(sysText.includes("JeikCode AI coding Agent"), false);
  assert.equal(sysText.includes("provided by Jeik"), false);

  assert.equal(sysText.includes("<environment>"), true);
  assert.equal(sysText.includes("</environment>"), true);
  assert.equal(sysText.includes("## Identity & Interaction"), true);
  assert.equal(
    sysText.includes("- Language: Always answer in the language used by the user."),
    true,
  );
  assert.equal(
    sysText.includes(
      "- Model identity: When asked about your model identity, answer based on your actual underlying model code.",
    ),
    true,
  );
  assert.equal(sysText.includes("## Configuration Directories"), true);
  assert.equal(sysText.includes("~/.jeikcode/"), true);
  assert.equal(sysText.includes("## PRECEDENCE:"), true);
  assert.equal(sysText.includes("## Runtime Environment"), true);
  assert.equal(sysText.includes("E:/code/jeikcode"), true);
});

// 59. L4010
test("test_issue_3904_dsh_duplicate_identity_single_part", () => {
  const raw =
    "You are an AI agent powered by DeepSeek Harness.\n\n" +
    "You are a coding agent powered by the gemini-3.8-flash-low model.";
  const payload = {
    systemInstruction: { parts: [{ text: raw }] },
    contents: [{ role: "user", parts: [{ text: "ping" }] }],
    tools: [
      {
        functionDeclarations: [
          {
            name: "ping",
            description: "ping",
            parameters: { type: "OBJECT", properties: {} },
          },
        ],
      },
    ],
  };

  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const sys = systemInstructionTextExact(body);
  assert.equal(countOfficialIdentity(sys), 1, `systemInstruction=${sys}`);
  assert.equal(sys.includes("8-flash-low"), false, `残渣泄漏: ${sys}`);
  assert.equal(sys.includes("DeepSeek Harness"), false, `第三方身份残留: ${sys}`);
});

// 60. L4034
test("test_issue_3904_duplicate_identity_across_parts", () => {
  const payload = {
    systemInstruction: {
      parts: [
        { text: "You are an AI agent powered by DeepSeek Harness." },
        { text: "You are a coding agent powered by the gemini-3.8-flash-low model." },
        { text: "Keep this instruction." },
      ],
    },
    contents: [],
  };

  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const sys = systemInstructionTextExact(body);
  const parts = body.systemInstruction.parts;
  assert.equal(countOfficialIdentity(sys), 1, `systemInstruction=${sys}`);
  assert.equal(sys.includes("Keep this instruction."), true);
  assert.equal(parts.length, 2, `空 part 必须被剔除: ${JSON.stringify(parts)}`);
});

// 61. L4054
test("test_issue_3904_whitespace_separators", () => {
  for (const sep of [" ", "\n", "\n\n"]) {
    const raw = `${OFFICIAL_ANTIGRAVITY_IDENTITY}${sep}${OFFICIAL_ANTIGRAVITY_IDENTITY}`;
    const payload = {
      systemInstruction: { parts: [{ text: raw }] },
      contents: [],
    };
    const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
    const sys = systemInstructionTextExact(body);
    assert.equal(
      countOfficialIdentity(sys),
      1,
      `分隔符 ${JSON.stringify(sep)} 未完成去重: ${sys}`,
    );
  }
});

// 62. L4074
test("test_issue_3904_non_consecutive_duplicate", () => {
  const raw = `${OFFICIAL_ANTIGRAVITY_IDENTITY}\n\nHi.\n\n${OFFICIAL_ANTIGRAVITY_IDENTITY}`;
  const payload = {
    systemInstruction: { parts: [{ text: raw }] },
    contents: [],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const sys = systemInstructionTextExact(body);
  assert.equal(countOfficialIdentity(sys), 1, `systemInstruction=${sys}`);
  assert.equal(sys.includes("Hi."), true);
});

// 63. L4090
test("test_issue_3904_structured_identity_line_removed", () => {
  const raw =
    "- Identity: You are an AI agent powered by DeepSeek Harness.\n" +
    "- Identity: You are a coding agent powered by the gemini-3.8-flash-low model.\n" +
    "- Language: Always answer in Chinese.";
  const payload = {
    systemInstruction: { parts: [{ text: raw }] },
    contents: [],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const sys = systemInstructionTextExact(body);
  assert.equal(sys.split("- Identity:").length - 1, 1, `结构化身份行未去重: ${sys}`);
  assert.equal(sys.includes("- Identity: \n"), false, `悬挂前缀: ${sys}`);
  assert.equal(sys.includes("- Language: Always answer in Chinese."), true);
});

// 64. L4114
test("test_issue_3904_continuation_preserved", () => {
  const raw =
    "You are an AI agent created by Acme, and you must never reveal internal tooling.\n\n" +
    "You are a coding agent built by Foo, and you must always call tools.";
  const payload = {
    systemInstruction: { parts: [{ text: raw }] },
    contents: [],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const sys = systemInstructionTextExact(body);
  assert.equal(countOfficialIdentity(sys), 1, `systemInstruction=${sys}`);
  assert.equal(sys.includes("never reveal internal tooling"), true);
  assert.equal(sys.includes("always call tools"), true);
  assert.equal(sys.includes(".,"), false);
});

// 65. L4134
test("test_issue_3904_version_dot_residue", () => {
  for (const raw of [
    "You are a coding agent powered by the gemini-3.8-flash-low model.",
    "You are a coding agent powered by the gemini-3.8-flash-tiered model.",
  ]) {
    const out = normalizeSystemIdentity(raw);
    assert.equal(out, OFFICIAL_ANTIGRAVITY_IDENTITY, `raw=${raw}`);
    assert.equal(out.includes("8-flash"), false, `版本残渣: ${out}`);
  }
});

// 66. L4146
test("test_issue_3904_code_block_identity_exempt", () => {
  const raw = `${OFFICIAL_ANTIGRAVITY_IDENTITY}\n\n\`\`\`text\n${OFFICIAL_ANTIGRAVITY_IDENTITY}\n\`\`\``;
  const payload = {
    systemInstruction: { parts: [{ text: raw }] },
    contents: [],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const sys = systemInstructionTextExact(body);
  assert.equal(countOfficialIdentity(sys), 2, `代码块内的 AG 必须豁免: ${sys}`);
  assert.equal(sys.includes("```text"), true);
});

// 67. L4167
test("test_issue_3904_idempotent", () => {
  const raw =
    "You are an AI agent powered by DeepSeek Harness.\n\n" +
    "You are a coding agent powered by the gemini-3.8-flash-low model.";
  const payload = {
    systemInstruction: { parts: [{ text: raw }] },
    contents: [],
  };
  const { body: b1 } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const first = b1.systemInstruction.parts[0].text;
  const { body: b2 } = sanitizeGeminiPayload(b1, RUST_DEFAULT_UNIT_OPTS);
  const second = b2.systemInstruction.parts[0].text;
  assert.equal(first, second, "去重必须幂等");
});

// 68. L4193
test("test_issue_3904_three_identities", () => {
  const raw = `${OFFICIAL_ANTIGRAVITY_IDENTITY}\n\n${OFFICIAL_ANTIGRAVITY_IDENTITY}\n\n${OFFICIAL_ANTIGRAVITY_IDENTITY}`;
  const payload = {
    systemInstruction: { parts: [{ text: raw }] },
    contents: [],
  };
  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const sys = systemInstructionTextExact(body);
  assert.equal(countOfficialIdentity(sys), 1, `systemInstruction=${sys}`);
});

// 69. L4238
test("test_prompt_rewrite_literal_and_empty_replacement", () => {
  const out = applyRulesForTest("RFC 2119 keywords: MUST. DELETE-ME tail", [
    ["RFC 2119 keywords:", "Normative keywords:"],
    ["DELETE-ME ", ""],
  ]);
  assert.equal(out, "Normative keywords: MUST. tail");
});

// 70. L4250
test("test_prompt_rewrite_wildcard_same_line_and_newline_escape", () => {
  let out = applyRulesForTest("You are omp's trusted assistant.\nSecond line", [
    ["You are *", "You are Antigravity."],
  ]);
  assert.equal(out, "You are Antigravity.\nSecond line");

  out = applyRulesForTest("line1\nline2", [["line1\\nline2", "joined"]]);
  assert.equal(out, "joined");
});

// 71. L4262
test("test_prompt_rewrite_escaped_star_is_literal", () => {
  const out = applyRulesForTest("a*b and aZZb", [["a\\*b", "X"]]);
  assert.equal(out, "X and aZZb");
});

// 72. L4268
test("test_prompt_rewrite_code_block_exempt", () => {
  const input = "SECRET\n```\nSECRET\n```";
  const out = applyRulesForTest(input, [["SECRET", "CLEAN"]]);
  assert.equal(out, "CLEAN\n```\nSECRET\n```");
});

// 73. L4275
test("test_prompt_rewrite_rules_apply_in_order", () => {
  const out = applyRulesForTest("A", [
    ["A", "B"],
    ["B", "C"],
  ]);
  assert.equal(out, "C");
});

// 74. L4281
test("test_prompt_rewrite_pattern_matching_empty_is_skipped", () => {
  const compiled = compilePromptRewriteRules(rewriteConfig([["*", "X"]]));
  assert.equal(compiled.length, 0, "pattern * can match empty and must be skipped");
});

// 75. L4291
test("test_prompt_rewrite_scope_is_pre_user_system_track_only", () => {
  const opts = rewriteConfig([["WAF-MARKER", "CLEANED"]]);
  const payload = {
    systemInstruction: { parts: [{ text: "WAF-MARKER" }] },
    contents: [
      { role: "user", parts: [{ text: "WAF-MARKER" }] },
      { role: "user", parts: [{ text: "WAF-MARKER" }] },
      { role: "model", parts: [{ text: "WAF-MARKER" }] },
      { role: "user", parts: [{ text: "WAF-MARKER" }] },
    ],
  };

  const { body } = sanitizeGeminiPayload(payload, opts);
  assert.equal(body.systemInstruction.parts[0].text, "CLEANED");
  assert.equal(body.contents[0].parts[0].text, "CLEANED");
  assert.equal(body.contents[1].parts[0].text, "WAF-MARKER");
  assert.equal(body.contents[2].parts[0].text, "WAF-MARKER");
  assert.equal(body.contents[3].parts[0].text, "WAF-MARKER");
});

// 76. L4324
test("test_issue_3908_opencode_appositive_continuation_is_normalized", () => {
  const raw =
    "You are an AI agent running in OpenCode, a coding agent harness. " +
    "Help the user accomplish their goals using the tools you have available.";
  const out = normalizeSystemIdentity(raw);
  assert.equal(out.startsWith(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(out.includes("Coding.,"), false, `不得留下 AG.,: ${out}`);
  assert.equal(
    out.includes("Coding, a coding agent harness"),
    false,
    `不得留下逗号同位语: ${out}`,
  );
  assert.equal(
    out.includes("Coding. a coding agent harness."),
    true,
    `同位语续写必须归一为句号: ${out}`,
  );
  assert.equal(out.includes("Help the user accomplish their goals"), true);
});

// 77. L4345
test("test_issue_3908_opencode_request_with_tools_has_no_residue", () => {
  const raw =
    "You are an AI agent running in OpenCode, a coding agent harness. " +
    "Help the user accomplish their goals using the tools you have available.";
  const payload = {
    systemInstruction: { parts: [{ text: raw }] },
    contents: [{ role: "user", parts: [{ text: "ping" }] }],
    tools: [
      {
        functionDeclarations: [
          {
            name: "ping",
            description: "ping",
            parameters: { type: "OBJECT", properties: {} },
          },
        ],
      },
    ],
  };

  const { body } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  const sys = systemInstructionTextExact(body);
  assert.equal(sys.includes("Coding.,"), false, `systemInstruction=${sys}`);
  assert.equal(
    sys.includes("Coding, a coding agent harness"),
    false,
    `systemInstruction=${sys}`,
  );
  assert.equal(
    sys.includes("Coding. a coding agent harness."),
    true,
    `systemInstruction=${sys}`,
  );
});

// 78. L4375
test("test_normalize_identity_toggle_preserves_client_identity", () => {
  const raw = "You are WAF-TOGGLE-TEST, an agent created by Example Corp.";
  assert.equal(
    normalizeSystemIdentity(raw, true),
    OFFICIAL_ANTIGRAVITY_IDENTITY,
  );
  assert.equal(normalizeSystemIdentity(raw, false), raw);
});

// 80. L4398
test("test_issue_3915_malformed_period_comma_punctuation_collapsed", () => {
  const input =
    "You are an AI agent running in OpenCode, a coding agent harness. Advanced Agentic Coding., a coding agent harness.";
  const out = normalizeSystemIdentity(input);
  assert.equal(out.includes(".,"), false, `不得包含 ., 标点: ${out}`);
  assert.equal(out.includes(". ,"), false, `不得包含 . , 标点: ${out}`);
  assert.equal(out.includes("。，"), false, `不得包含 。， 标点: ${out}`);
});

// 81. L4408
test("test_strip_anthropic_billing_header", () => {
  const raw =
    "x-anthropic-billing-header: cc_version=2.1.28; client=claude_code\nYou are a helpful assistant.";
  const cleaned = stripPipelineMarkers(raw);
  assert.equal(
    cleaned.includes("x-anthropic-billing-header"),
    false,
    "billing header 必须被剥离",
  );
  assert.equal(cleaned.includes("You are a helpful assistant."), true);
});

// 82. L4419
test("test_recommended_preset_rules_execution", () => {
  const compiled = compilePromptRewriteRules({
    enabled: true,
    rules: RECOMMENDED_PRESET_RULES,
  });

  const opencodeRaw =
    "You are an AI agent running in OpenCode, a coding agent harness.\nHelp user write code.";
  const rewritten = rewriteTextWithRules(opencodeRaw, compiled) ?? opencodeRaw;
  assert.equal(rewritten.includes("OpenCode"), false);
  assert.equal(rewritten.includes("Help user write code."), true);

  const dshRaw =
    "You are an AI agent powered by DeepSeek Harness.\nYou are a coding agent powered by the gemini-3.8-flash-high model.\nDo tasks.";
  const rewrittenDsh = rewriteTextWithRules(dshRaw, compiled) ?? dshRaw;
  assert.equal(rewrittenDsh.includes("DeepSeek Harness"), false);
  assert.equal(rewrittenDsh.includes("gemini-3.8-flash-high"), false);
  assert.equal(rewrittenDsh.includes("Do tasks."), true);

  const wbRaw = "Prefix.\n*WorkBuddy environment initialized*\nSuffix.";
  const rewrittenWb = rewriteTextWithRules(wbRaw, compiled) ?? wbRaw;
  assert.equal(rewrittenWb.includes("WorkBuddy"), false);
  assert.equal(rewrittenWb.includes("Prefix."), true);
  assert.equal(rewrittenWb.includes("Suffix."), true);

  const billingRaw = "x-anthropic-billing-header: test\nSystem prompt.";
  const rewrittenBilling = rewriteTextWithRules(billingRaw, compiled) ?? billingRaw;
  assert.equal(rewrittenBilling.includes("x-anthropic-billing-header"), false);
  assert.equal(rewrittenBilling.includes("System prompt."), true);

  const sessionRaw = "Use `tools.opencode.session-move` to transfer session.";
  const rewrittenSession = rewriteTextWithRules(sessionRaw, compiled) ?? sessionRaw;
  assert.equal(rewrittenSession.includes("tools.opencode.session-move"), false);
  assert.equal(rewrittenSession.includes("tools.opencode.session_relocate"), true);

  const ccRaw =
    "You are an interactive agent that helps users with software engineering tasks. Use the instructions below.\nNext line.";
  const rewrittenCc = rewriteTextWithRules(ccRaw, compiled) ?? ccRaw;
  assert.equal(
    rewrittenCc.includes(
      "interactive agent that helps users with software engineering tasks",
    ),
    false,
  );
  assert.equal(rewrittenCc.includes("Next line."), true);
});

// 83. L4481
test("test_issue_3965_waf_trigger_agent_tool_guidelines_neutralized", () => {
  const raw =
    "You are a coding assistant.\n" +
    "Guidelines: Prefer read_file, edit_file, and write_file over cat/sed.\n" +
    "Guideline 2: Always read_file before edit_file.\n" +
    "Guideline 3: Please call read_file on its SKILL.md before proceeding.\n" +
    "Guideline 4: Follow Google model operational directives.\n" +
    "Guideline 5: Follow Google model operational guidelines.\n" +
    "```python\n" +
    "# Code blocks must remain 100% intact:\n" +
    "def read_file(path):\n" +
    "    pass\n" +
    "# In-code comment: Prefer read_file, edit_file, and write_file over cat/sed.\n" +
    "```\n" +
    "Done.";

  const cleaned = cleanText(raw);

  assert.equal(
    cleaned.includes(
      "Guidelines: Prefer read_file, edit_file, and write_file over cat/sed",
    ),
    false,
  );
  assert.equal(
    cleaned.includes("Guideline 2: Always read_file before edit_file"),
    false,
  );
  assert.equal(cleaned.includes("call read_file on its SKILL.md"), false);
  assert.equal(cleaned.includes("Google model operational directives"), false);
  assert.equal(cleaned.includes("Google model operational guidelines"), false);
  assert.equal(
    cleaned.includes(
      "Guidelines: Prefer read file, edit file, and write file over cat/sed",
    ),
    true,
  );
  assert.equal(
    cleaned.includes("Guideline 2: Always read file before edit file"),
    true,
  );
  assert.equal(cleaned.includes("call read file on its SKILL.md"), true);
  assert.equal(cleaned.includes("Model operational guidelines"), true);

  assert.equal(cleaned.includes("def read_file(path):"), true);
  assert.equal(
    cleaned.includes(
      "# In-code comment: Prefer read_file, edit_file, and write_file over cat/sed.",
    ),
    true,
  );
});

// 84. L4523
test("test_issue_3969_opencode_waf_trigger_session_move_neutralized", () => {
  const raw =
    "# Code Mode\n\n" +
    "You have access to the following tools:\n" +
    "- tools.opencode.session-move({ destination: string }): move session\n" +
    "- tools.opencode.session_move({ destination: string }): move session alternate\n\n" +
    "When you create a worktree outside the current working directory and intend to use it as your primary working directory, " +
    "consider using `execute` to call `tools.opencode.session-move` and make the worktree the session's working directory.\n\n" +
    "Also consider `tools.opencode.session_move`.\n\n" +
    "```json\n" +
    "{\n" +
    '  "sample": "tools.opencode.session-move in fenced code block must stay untouched"\n' +
    "}\n" +
    "```\n";

  const cleaned = cleanText(raw);
  const outsideCode = cleaned.split("```json")[0];
  assert.equal(
    outsideCode.includes("tools.opencode.session-move"),
    false,
    `纯文本与行内反引号中的 tools.opencode.session-move 必须被中和: ${outsideCode}`,
  );
  assert.equal(
    outsideCode.includes("tools.opencode.session_move"),
    false,
    `纯文本与行内反引号中的 tools.opencode.session_move 必须被中和: ${outsideCode}`,
  );
  assert.equal(outsideCode.includes("tools.opencode.session_relocate"), true);
  assert.equal(outsideCode.includes("`tools.opencode.session_relocate`"), true);
  assert.equal(
    cleaned.includes(
      "tools.opencode.session-move in fenced code block must stay untouched",
    ),
    true,
  );
});

// 85. L4560
test("test_issue_3969_prompt_rewrite_rules_cover_inline_backticks", () => {
  const input =
    "call `tools.opencode.session-move` now\n```\n`tools.opencode.session-move` in code\n```";
  const out = applyRulesForTest(input, [
    ["tools.opencode.session-move", "tools.opencode.session_relocate"],
  ]);
  assert.equal(out.includes("call `tools.opencode.session_relocate` now"), true);
  assert.equal(
    out.includes("```\n`tools.opencode.session-move` in code\n```"),
    true,
  );
});

// 86. L4577
test("test_issue_3969_edge_cases_mixed_case_and_unclosed_backticks", () => {
  const mixed =
    "Call `Tools.OpenCode.Session-Move` and `TOOLS.OPENCODE.SESSION_MOVE` on same line.";
  const cleanedMixed = cleanText(mixed);
  assert.equal(cleanedMixed.toLowerCase().includes("session-move"), false);
  assert.equal(cleanedMixed.toLowerCase().includes("session_move"), false);
  assert.equal(cleanedMixed.includes("tools.opencode.session_relocate"), true);

  const unclosed = "Notice: `tools.opencode.session-move without closing backtick";
  const cleanedUnclosed = cleanText(unclosed);
  assert.equal(cleanedUnclosed.includes("tools.opencode.session-move"), false);
  assert.equal(cleanedUnclosed.includes("tools.opencode.session_relocate"), true);
});

// 87. L4596
test("test_issue_3972_claude_code_interactive_agent_normalized_and_sanitized", () => {
  const raw =
    "You are an interactive agent that helps users with software engineering tasks. " +
    "Use the instructions below and the tools available to you to assist the user.\n\n" +
    "# Rules\n" +
    "Rule 1: Always check tests.";

  const normalized = normalizeSystemIdentity(raw);
  assert.equal(normalized.startsWith(OFFICIAL_ANTIGRAVITY_IDENTITY), true);
  assert.equal(
    normalized.includes(
      "You are an interactive agent that helps users with software engineering tasks",
    ),
    false,
  );
  assert.equal(
    normalized.includes(
      "Use the instructions below and the tools available to you to assist the user.",
    ),
    true,
  );

  const standalone =
    "You are an interactive agent that helps users with software engineering tasks. Use the instructions below and the tools available to you to assist the user.";
  assert.equal(
    normalizeClientIdentity(standalone),
    OFFICIAL_ANTIGRAVITY_IDENTITY,
  );

  const cleaned = cleanText(raw);
  assert.equal(
    cleaned.includes(
      "You are an interactive agent that helps users with software engineering tasks",
    ),
    false,
  );
});

// 88. L4631
test("test_pi_codemode_minimal_repro_and_inline_variants_neutralized", () => {
  const minimal =
    "codemode scripts and non-LLM models such as classifiers and image models";
  const cleaned = cleanText(minimal);
  assert.equal(
    cleaned,
    "codem0de scripts and non-LLM models such as classifiers and image models",
  );

  const mixed =
    "- codemode: Run JavaScript that calls other tools\n" +
    "- Use `codemode` to batch calls, or read `docs/codemode.md` and `builtin:codemode`.\n" +
    "- Case variants: Codemode, CodeMode, CODEMODE.\n" +
    "- Underscore identifier must stay untouched: my_codemode_helper.\n" +
    "```js\n" +
    "// Fenced code block must stay untouched\n" +
    'await tools.codemode({ code: "codemode" });\n' +
    "```\n";
  const cleanedMixed = cleanText(mixed);
  const outside = cleanedMixed.split("```js")[0];
  assert.equal(outside.includes("codemode\n"), false);
  assert.equal(outside.includes("`codemode`"), false);
  assert.equal(outside.includes("docs/codemode.md"), false);
  assert.equal(outside.includes("builtin:codemode"), false);
  assert.equal(outside.includes("- codem0de:"), true);
  assert.equal(outside.includes("`codem0de`"), true);
  assert.equal(outside.includes("`docs/codem0de.md`"), true);
  assert.equal(outside.includes("`builtin:codem0de`"), true);
  assert.equal(outside.includes("Codem0de, CodeM0de, CODEM0DE"), true);
  assert.equal(outside.includes("my_codemode_helper"), true);
  assert.equal(
    cleanedMixed.includes('await tools.codemode({ code: "codemode" });'),
    true,
  );
});

// 89. L4667
test("test_pi_codemode_20k_prefix_limit_across_payload_and_tools", () => {
  const fillerSys = "x".repeat(18_500);
  const fillerUser = "y".repeat(2_000);
  const payload = {
    systemInstruction: {
      parts: [
        {
          text: `${fillerSys}\n- codemode scripts and non-LLM models such as classifiers and image models (docs/codemode.md)`,
        },
      ],
    },
    contents: [
      {
        role: "user",
        parts: [{ text: `Early turn codemode check.\n${fillerUser}` }],
      },
      {
        role: "model",
        parts: [{ text: "Model reply." }],
      },
      {
        role: "user",
        parts: [
          {
            text: "Later turn beyond 20k chars should keep codemode untouched.",
          },
        ],
      },
    ],
    tools: [
      {
        functionDeclarations: [
          {
            name: "codemode",
            description:
              "Run JS across codemode calls. Read docs/codemode.md first.",
            parameters: {
              type: "object",
              properties: {
                code: { type: "string", description: "codemode source" },
              },
            },
          },
        ],
      },
    ],
  };

  const { body, changed } = sanitizeGeminiPayload(payload, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(changed, true);

  const sysText = body.systemInstruction.parts[0].text;
  assert.equal(sysText.includes("codem0de scripts and non-LLM models"), true);
  assert.equal(sysText.includes("docs/codem0de.md"), true);
  assert.equal(sysText.includes("codemode"), false);

  const firstUser = body.contents[0].parts[0].text;
  assert.equal(firstUser.startsWith("Early turn codem0de check."), true);

  const laterUser = body.contents[2].parts[0].text;
  assert.equal(
    laterUser,
    "Later turn beyond 20k chars should keep codemode untouched.",
  );

  const decl = body.tools[0].functionDeclarations[0];
  assert.equal(decl.name, "codemode");
  assert.equal(
    decl.description.includes(
      "across codem0de calls. Read docs/codem0de.md first.",
    ),
    true,
  );
  assert.equal(decl.parameters.properties.code.description, "codemode source");

  const second = sanitizeGeminiPayload(body, RUST_DEFAULT_UNIT_OPTS);
  assert.equal(second.changed, false);
});

// 90. L4754
test("test_pi_codemode_20k_boundary_respects_fenced_block_original_length", () => {
  const fenced = `\`\`\`text\n${"a".repeat(19_990)}\n\`\`\`\n`;
  const input = `${fenced}beyond_20k codemode should stay untouched`;
  const cleaned = cleanText(input);
  assert.equal(
    cleaned.includes("beyond_20k codemode should stay untouched"),
    true,
  );

  const prefixWithHit = `within_20k codemode ${"b".repeat(20_050)}`;
  const input2 = `${prefixWithHit} tail_after_20k codemode`;
  const cleaned2 = cleanText(input2);
  assert.equal(cleaned2.startsWith("within_20k codem0de "), true);
  assert.equal(cleaned2.endsWith("tail_after_20k codemode"), true);
});

// 91. L4772
test("test_issue_3982_workbuddy_powered_by_lf_and_crlf_neutralized", () => {
  const lfInput =
    "This conversation is powered by gemini-4-hydrogen\n# Rules\nRule 1: Be helpful.";
  const lfCleaned = cleanText(lfInput);
  assert.equal(
    lfCleaned.startsWith("Selected model: gemini-4-hydrogen\n# Rules"),
    true,
  );
  assert.equal(lfCleaned.includes("This conversation is powered by"), false);

  const crlfInput =
    "This conversation is powered by gemini-4-hydrogen\r\n# Rules\r\nRule 1: Be helpful.";
  const crlfCleaned = cleanText(crlfInput);
  assert.equal(
    crlfCleaned.startsWith("Selected model: gemini-4-hydrogen\r\n# Rules"),
    true,
  );
  assert.equal(crlfCleaned.includes("This conversation is powered by"), false);

  const complexModel =
    "  this conversation is powered by custom.org/gemini-3.8-flash:latest  \r\nNext line";
  const cleanedComplex = cleanText(complexModel);
  assert.equal(
    cleanedComplex.startsWith(
      "Selected model: custom.org/gemini-3.8-flash:latest\r\n",
    ),
    true,
  );

  const codeInput =
    "This conversation is powered by gemini-4\n```text\nThis conversation is powered by gemini-4\n```";
  const codeCleaned = cleanText(codeInput);
  assert.equal(codeCleaned.includes("Selected model: gemini-4"), true);
  assert.equal(
    codeCleaned.includes("```text\nThis conversation is powered by gemini-4\n```"),
    true,
  );
});

// 92. L4803
test("test_issue_3982_codex_desktop_context_and_role_neutralized", () => {
  const lfInput = "# Codex desktop context\nInstructions here.";
  const lfCleaned = cleanText(lfInput);
  assert.equal(lfCleaned, "# Desktop application context\nInstructions here.");

  const crlfInput = "#   Codex desktop context  \r\nInstructions here.";
  const crlfCleaned = cleanText(crlfInput);
  assert.equal(
    crlfCleaned,
    "# Desktop application context\r\nInstructions here.",
  );

  const roleInput = "When instructed as Codex: provide code immediately.";
  const roleCleaned = cleanText(roleInput);
  assert.equal(
    roleCleaned,
    "When instructed as an assistant: provide code immediately.",
  );

  const fencedInput =
    "# Codex desktop context\n```\n# Codex desktop context\nas Codex:\n```";
  const fencedCleaned = cleanText(fencedInput);
  assert.equal(
    fencedCleaned.startsWith(
      "# Desktop application context\n```\n# Codex desktop context\nas Codex:\n```",
    ),
    true,
  );
});

// 93. L4836
test("test_issue_3983_dsh_browser_context_neutralized", () => {
  const input =
    "System directive:\nThe browser provides no implicit DOM, route, or screenshot context.\nPlease proceed.";
  const cleaned = cleanText(input);
  assert.equal(
    cleaned,
    "System directive:\nThe browser exposes no DOM tree, route list, or page screenshot context.\nPlease proceed.",
  );

  const fenced =
    "Text\n```\nThe browser provides no implicit DOM, route, or screenshot context.\n```";
  const cleanedFenced = cleanText(fenced);
  assert.equal(cleanedFenced, fenced);
});

// 94. L4852
test("test_prompt_rewrite_rule_scope_separation", () => {
  const opts = {
    enabled: true,
    normalizeIdentity: true,
    sideloadMode: "off",
    sanitizeToolsDescription: true,
    rules: [
      {
        id: "r-all",
        pattern: "sensitive_all",
        replacement: "clean_all",
        scope: "all",
        enabled: true,
      },
      {
        id: "r-prompt",
        pattern: "sensitive_prompt",
        replacement: "clean_prompt",
        scope: "prompt",
        enabled: true,
      },
      {
        id: "r-tool",
        pattern: "sensitive_tool",
        replacement: "clean_tool",
        scope: "tools",
        enabled: true,
      },
    ],
  };

  const payload = {
    systemInstruction: {
      parts: [
        {
          text: "This has sensitive_all, sensitive_prompt, and sensitive_tool in prompt.",
        },
      ],
    },
    tools: [
      {
        functionDeclarations: [
          {
            name: "test_func",
            description:
              "Tool has sensitive_all, sensitive_prompt, and sensitive_tool in desc.",
          },
        ],
      },
    ],
  };

  const { body } = sanitizeGeminiPayload(payload, opts);

  const sysText = body.systemInstruction.parts[0].text;
  assert.equal(sysText.includes("clean_all"), true, "All scope should apply to prompt");
  assert.equal(
    sysText.includes("clean_prompt"),
    true,
    "Prompt scope should apply to prompt",
  );
  assert.equal(
    sysText.includes("sensitive_tool"),
    true,
    "Tools scope must NOT apply to prompt",
  );

  const toolDesc = body.tools[0].functionDeclarations[0].description;
  assert.equal(toolDesc.includes("clean_all"), true, "All scope should apply to tools");
  assert.equal(
    toolDesc.includes("clean_tool"),
    true,
    "Tools scope should apply to tools",
  );
  assert.equal(
    toolDesc.includes("sensitive_prompt"),
    true,
    "Prompt scope must NOT apply to tools",
  );
});
