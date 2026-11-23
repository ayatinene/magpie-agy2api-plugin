// Writes synthetic request bodies shaped like real agent traffic, each with the result
// Node produces for it, as NDJSON for main.go.
//
//   node gen-corpus.mjs corpus.ndjson
import { writeFileSync } from "node:fs";
import { onProvider } from "../../middleware.mjs";

const PROSE =
  "The function parses the configuration file and returns a normalized object; callers must handle the error path explicitly. ";
const CJK = "请在修改代码之前先阅读相关文件，并遵循项目约定；完成后说明改动原因与验证结果。";

function filler(length, seed = PROSE) {
  let out = "";
  for (let i = 0; out.length < length; i += 1) {
    out += `${seed}Step ${i}: update src/module_${i % 97}.ts and re-run the unit tests.\n`;
  }
  return out.slice(0, length);
}

const AGENT_SYSTEM = `You are an interactive agent that helps users with software engineering tasks. Use the instructions below and the tools available to you to assist the user.

IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.

# Harness
 - Text you output outside of tool use is displayed to the user as Github-flavored markdown in a terminal.
 - Prefer the dedicated file/search tools over shell commands when one fits.

# Doing tasks
${filler(4000)}`;

const tools = (count) =>
  Array.from({ length: count }, (_, i) => ({
    name: `Tool${i}`,
    description: filler(1500, `Runs operation ${i} in the workspace. Use it to inspect or modify files. `),
    input_schema: { type: "object", properties: { path: { type: "string" } } },
  }));

// First user turn the way coding agents send it: several injected reminder blocks, then the question.
const firstTurn = (reminderChars) => [
  "<system-reminder>\n# Environment\nPrimary working directory: /home/dev/project\nPlatform: linux\n</system-reminder>",
  "<system-reminder>\nYou are powered by the model named example/model-1.\n</system-reminder>",
  `<system-reminder>\nProject notes follow.\n\n---\nname: project-code-style\ndescription: 代码风格约定\n---\n\n${filler(reminderChars, CJK)}\n</system-reminder>`,
  "Please fix the flaky test in the billing module and explain what was wrong.",
];

function anthropic({ turns, textChars, toolResultChars, reminderChars = 30000 }) {
  const messages = [{ role: "user", content: firstTurn(reminderChars).map((text) => ({ type: "text", text })) }];
  for (let t = 0; t < turns; t += 1) {
    messages.push({
      role: "assistant",
      content: [
        { type: "thinking", thinking: filler(500), signature: `sig${t}` },
        { type: "text", text: filler(textChars, "I'll look at the retry path first, then the test itself. ") },
        { type: "tool_use", id: `toolu_${t}`, name: "Tool1", input: { path: "/home/dev/project/src/a.ts" } },
      ],
    });
    messages.push({
      role: "user",
      content: [{ type: "tool_result", tool_use_id: `toolu_${t}`, content: filler(toolResultChars) }],
    });
  }
  return {
    model: "example-model",
    max_tokens: 32000,
    stream: true,
    system: [
      { type: "text", text: "x-anthropic-billing-header: cc_version=2.1.80; cc_entrypoint=cli; cch=00000;" },
      { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
      { type: "text", text: AGENT_SYSTEM },
    ],
    tools: tools(12),
    messages,
  };
}

function chat({ turns, textChars, toolResultChars }) {
  const messages = [
    { role: "system", content: `You are opencode, an interactive CLI tool that helps users with software engineering tasks.\n${filler(6000)}` },
    { role: "user", content: firstTurn(30000).map((text) => ({ type: "text", text })) },
  ];
  for (let t = 0; t < turns; t += 1) {
    messages.push({
      role: "assistant",
      content: filler(textChars),
      tool_calls: [{ id: `call_${t}`, type: "function", function: { name: "Tool1", arguments: "{}" } }],
    });
    messages.push({ role: "tool", tool_call_id: `call_${t}`, content: t % 7 === 0 ? "" : filler(toolResultChars) });
  }
  return {
    model: "example-model",
    messages,
    tools: tools(12).map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.input_schema } })),
  };
}

function responses({ turns, textChars, toolResultChars }) {
  const input = [
    { type: "message", role: "developer", content: [{ type: "input_text", text: "<permissions instructions>\nApproval policy is never.\n</permissions instructions>" }] },
    { type: "message", role: "user", content: firstTurn(20000).map((text) => ({ type: "input_text", text })) },
  ];
  for (let t = 0; t < turns; t += 1) {
    input.push({ type: "reasoning", id: `rs_${t}`, summary: [], encrypted_content: `enc${t}` });
    input.push({ type: "function_call", call_id: `call_${t}`, name: "shell", arguments: "{}" });
    input.push({ type: "function_call_output", call_id: `call_${t}`, output: filler(toolResultChars) });
    input.push({ type: "message", role: "assistant", content: [{ type: "output_text", text: filler(textChars) }] });
  }
  return {
    model: "example-model",
    instructions: `You are Codex, based on GPT-5. You are running as a coding agent in the Codex CLI on a user's computer.\n\n# Codex desktop context\n${filler(5000)}`,
    input,
    tools: [{ type: "function", name: "shell", description: "Runs a shell command.", parameters: { type: "object", properties: {} } }],
  };
}

function gemini({ turns, textChars, toolResultChars }) {
  const contents = [{ role: "user", parts: firstTurn(30000).map((text) => ({ text })) }];
  for (let t = 0; t < turns; t += 1) {
    contents.push({ role: "model", parts: [{ thought: true, text: "thinking", thoughtSignature: "c2ln" }, { text: filler(textChars) }, { functionCall: { name: "read", args: {} } }] });
    contents.push({ role: "user", parts: [{ functionResponse: { name: "read", response: { output: filler(toolResultChars) } } }] });
  }
  return {
    systemInstruction: { parts: [{ text: `You are Hermes Agent, an intelligent AI assistant created by Nous Research.\n${filler(8000)}` }] },
    contents,
    tools: [{ functionDeclarations: [{ name: "read", description: "call read_file on its SKILL.md", parameters: { type: "OBJECT", properties: {} } }] }],
  };
}

const cases = [
  ["anthropic-first-turn", "anthropic", anthropic({ turns: 0, textChars: 0, toolResultChars: 0 })],
  ["anthropic-1MB", "anthropic", anthropic({ turns: 120, textChars: 800, toolResultChars: 6000 })],
  ["anthropic-5MB", "anthropic", anthropic({ turns: 500, textChars: 800, toolResultChars: 8000 })],
  ["anthropic-text-heavy-3MB", "anthropic", anthropic({ turns: 300, textChars: 6000, toolResultChars: 3000 })],
  ["anthropic-big-reminders-200KB", "anthropic", anthropic({ turns: 5, textChars: 500, toolResultChars: 2000, reminderChars: 200000 })],
  ["chat-first-turn", "chat", chat({ turns: 0, textChars: 0, toolResultChars: 0 })],
  ["chat-5MB", "chat", chat({ turns: 500, textChars: 800, toolResultChars: 8000 })],
  ["responses-first-turn", "responses", responses({ turns: 0, textChars: 0, toolResultChars: 0 })],
  ["responses-5MB", "responses", responses({ turns: 500, textChars: 800, toolResultChars: 8000 })],
  ["gemini-first-turn", "gemini", gemini({ turns: 0, textChars: 0, toolResultChars: 0 })],
  ["gemini-5MB", "gemini", gemini({ turns: 500, textChars: 800, toolResultChars: 8000 })],
  ["anthropic-sideload-auto", "anthropic", anthropic({ turns: 3, textChars: 500, toolResultChars: 2000 }), { promptRewrite: { sideload_mode: "auto" } }],
  ["anthropic-sanitizer-off", "anthropic", anthropic({ turns: 0, textChars: 0, toolResultChars: 0 }), { promptSanitizer: false }],
];

const out = process.argv[2];
if (!out) {
  console.error("usage: node gen-corpus.mjs <corpus.ndjson>");
  process.exit(2);
}
const lines = cases.map(([name, protocol, body, options]) => {
  const expected = onProvider(body, { protocol, provider: { id: "agy2api" }, options: options ?? {} }) ?? null;
  return JSON.stringify({ name, protocol, body, ...(options ? { options } : {}), expected });
});
writeFileSync(out, `${lines.join("\n")}\n`);
console.log(`wrote ${cases.length} cases to ${out}`);
