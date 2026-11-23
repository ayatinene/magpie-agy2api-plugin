import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const DEFAULT_PAGE_SERVICE_PORT = 18417;
export const UPSTREAM_AGT_BETA_CONFIG_URL =
  "https://raw.githubusercontent.com/lbjlaq/Antigravity-Manager/beta/src-tauri/src/proxy/config.rs";
export const MAX_RULES = 64;
export const MAX_PATTERN_CHARS = 8192;
export const MAX_REPLACEMENT_CHARS = 16384;
export const MAX_UPSTREAM_BODY_BYTES = 2 * 1024 * 1024;
export const UPSTREAM_CACHE_TTL_MS = 60_000;

const PAGE_SERVICES_SYMBOL = Symbol.for("magpie.agy2api.pageServices");
const PAGE_SERVICES_PENDING_SYMBOL = Symbol.for("magpie.agy2api.pageServicesPending");

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_UI_DIR = path.resolve(__dirname, "..", "ui");

const VALID_SCOPES = Object.freeze({
  Prompt: "prompt",
  All: "all",
  Tools: "tools",
});

const HTML_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'self'";

const STATIC_ROUTES = Object.freeze({
  "/sanitizer-panel.css": { file: "sanitizer-panel.css", contentType: "text/css; charset=utf-8" },
  "/sanitizer-panel.js": { file: "sanitizer-panel.js", contentType: "text/javascript; charset=utf-8" },
  "/service-bridge.js": { file: "service-bridge.js", contentType: "text/javascript; charset=utf-8" },
  "/icon.svg": { file: "icon.svg", contentType: "image/svg+xml" },
});

function getPageServiceRegistry() {
  if (!(globalThis[PAGE_SERVICES_SYMBOL] instanceof Map)) {
    globalThis[PAGE_SERVICES_SYMBOL] = new Map();
  }
  return globalThis[PAGE_SERVICES_SYMBOL];
}

function getPendingRegistry() {
  if (!(globalThis[PAGE_SERVICES_PENDING_SYMBOL] instanceof Map)) {
    globalThis[PAGE_SERVICES_PENDING_SYMBOL] = new Map();
  }
  return globalThis[PAGE_SERVICES_PENDING_SYMBOL];
}

function resolvePort(port) {
  const n = typeof port === "number" ? port : Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : DEFAULT_PAGE_SERVICE_PORT;
}

function isIdentStart(ch) {
  return (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch === "_";
}

function isIdentChar(ch) {
  return isIdentStart(ch) || (ch >= "0" && ch <= "9");
}

/**
 * Skip a Rust line or nested block comment starting at `pos`.
 * Returns the index after the comment, or `pos` if not at a comment.
 */
function skipRustComment(src, pos) {
  if (src[pos] !== "/") return pos;
  if (src[pos + 1] === "/") {
    const nl = src.indexOf("\n", pos + 2);
    return nl === -1 ? src.length : nl + 1;
  }
  if (src[pos + 1] === "*") {
    let depth = 1;
    let i = pos + 2;
    while (i < src.length && depth > 0) {
      if (src[i] === "/" && src[i + 1] === "*") {
        depth += 1;
        i += 2;
      } else if (src[i] === "*" && src[i + 1] === "/") {
        depth -= 1;
        i += 2;
      } else {
        i += 1;
      }
    }
    return i;
  }
  return pos;
}

/**
 * Skip a Rust char literal starting at `pos`, distinguishing `'x'` / `'\''`
 * from lifetime annotations like `'static`.
 */
function skipRustCharLiteral(src, pos) {
  if (src[pos] !== "'") return pos;
  if (pos + 1 >= src.length) return pos + 1;

  if (src[pos + 1] === "\\") {
    let i = pos + 2;
    if (i < src.length && src[i] === "u" && src[i + 1] === "{") {
      const endBrace = src.indexOf("}", i + 2);
      if (endBrace !== -1 && src[endBrace + 1] === "'") {
        return endBrace + 2;
      }
    } else if (i < src.length && src[i] === "x" && i + 3 < src.length && src[i + 3] === "'") {
      return i + 4;
    } else if (i + 1 < src.length && src[i + 1] === "'") {
      return i + 2;
    }
    return pos + 1;
  }

  if (pos + 2 < src.length && src[pos + 2] === "'" && src[pos + 1] !== "'" && src[pos + 1] !== "\n") {
    return pos + 3;
  }

  return pos + 1;
}

/**
 * Parse a Rust normal (`"..."`) or raw (`r"..."`, `r#"..."#`, ...) string literal at `pos`.
 * Returns `{ value, nextPos }` or `null` if `pos` is not at a string literal.
 */
function readRustStringLiteral(src, pos) {
  if (src[pos] === '"') {
    let out = "";
    let i = pos + 1;
    while (i < src.length) {
      const ch = src[i];
      if (ch === '"') {
        return { value: out, nextPos: i + 1 };
      }
      if (ch === "\\") {
        i += 1;
        if (i >= src.length) {
          throw new Error("Unterminated escape sequence in Rust string literal");
        }
        const esc = src[i];
        if (esc === '"' || esc === "'" || esc === "\\") {
          out += esc;
          i += 1;
        } else if (esc === "n") {
          out += "\n";
          i += 1;
        } else if (esc === "r") {
          out += "\r";
          i += 1;
        } else if (esc === "t") {
          out += "\t";
          i += 1;
        } else if (esc === "0") {
          out += "\0";
          i += 1;
        } else if (esc === "\n" || (esc === "\r" && src[i + 1] === "\n")) {
          // Rust string line continuation skips the newline and following ASCII whitespace
          while (i < src.length && (src[i] === " " || src[i] === "\t" || src[i] === "\n" || src[i] === "\r")) {
            i += 1;
          }
        } else if (esc === "x") {
          const hex = src.slice(i + 1, i + 3);
          if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
            throw new Error(`Invalid \\x escape in Rust string literal: \\x${hex}`);
          }
          out += String.fromCharCode(Number.parseInt(hex, 16));
          i += 3;
        } else if (esc === "u" && src[i + 1] === "{") {
          const closeBrace = src.indexOf("}", i + 2);
          if (closeBrace === -1) {
            throw new Error("Unterminated \\u{...} escape in Rust string literal");
          }
          const rawHex = src.slice(i + 2, closeBrace).replaceAll("_", "");
          if (!/^[0-9a-fA-F]{1,6}$/.test(rawHex)) {
            throw new Error(`Invalid \\u{...} escape in Rust string literal: ${rawHex}`);
          }
          const cp = Number.parseInt(rawHex, 16);
          if (cp > 0x10ffff) {
            throw new Error(`Out-of-range Unicode scalar in Rust string literal: ${rawHex}`);
          }
          out += String.fromCodePoint(cp);
          i = closeBrace + 1;
        } else {
          throw new Error(`Unsupported escape \\${esc} in Rust string literal`);
        }
        continue;
      }
      out += ch;
      i += 1;
    }
    throw new Error("Unterminated Rust string literal");
  }

  if (src[pos] === "r") {
    let i = pos + 1;
    while (i < src.length && src[i] === "#") {
      i += 1;
    }
    if (src[i] === '"') {
      const hashes = "#".repeat(i - pos - 1);
      const terminator = '"' + hashes;
      const contentStart = i + 1;
      const closeIdx = src.indexOf(terminator, contentStart);
      if (closeIdx === -1) {
        throw new Error("Unterminated Rust raw string literal");
      }
      return {
        value: src.slice(contentStart, closeIdx),
        nextPos: closeIdx + terminator.length,
      };
    }
  }

  return null;
}

/**
 * Advance `pos` past whitespace and Rust comments.
 */
function skipSpaceAndComments(src, pos) {
  let i = pos;
  while (i < src.length) {
    const ch = src[i];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      i += 1;
      continue;
    }
    if (ch === "/" && (src[i + 1] === "/" || src[i + 1] === "*")) {
      i = skipRustComment(src, i);
      continue;
    }
    break;
  }
  return i;
}

/**
 * Advance `pos` past a comment, string literal, or char literal if present.
 * Returns the new index, or `-1` if `pos` is ordinary code.
 */
function skipTriviaOrLiteral(src, pos) {
  if (src[pos] === "/" && (src[pos + 1] === "/" || src[pos + 1] === "*")) {
    return skipRustComment(src, pos);
  }
  const str = readRustStringLiteral(src, pos);
  if (str) {
    return str.nextPos;
  }
  if (src[pos] === "'") {
    return skipRustCharLiteral(src, pos);
  }
  return -1;
}

/**
 * Find matching closing delimiter for `openChar` (`(` or `{`) starting at `openPos`.
 */
function findMatchingDelimiter(src, openPos, openChar, closeChar) {
  let depth = 1;
  let i = openPos + 1;
  while (i < src.length && depth > 0) {
    const skipped = skipTriviaOrLiteral(src, i);
    if (skipped !== -1) {
      i = skipped;
      continue;
    }
    if (src[i] === openChar) {
      depth += 1;
    } else if (src[i] === closeChar) {
      depth -= 1;
      if (depth === 0) return i;
    }
    i += 1;
  }
  throw new Error(`Unbalanced '${openChar}...${closeChar}' in Rust source`);
}

/**
 * Locate `fn <fnName>` outside comments/strings and return its `{ ... }` body text.
 */
function extractFunctionBody(src, fnName) {
  let i = 0;
  while (i < src.length) {
    const skipped = skipTriviaOrLiteral(src, i);
    if (skipped !== -1) {
      i = skipped;
      continue;
    }

    if (isIdentStart(src[i])) {
      let end = i + 1;
      while (end < src.length && isIdentChar(src[end])) {
        end += 1;
      }
      const word = src.slice(i, end);
      if (word === "fn") {
        const nameStart = skipSpaceAndComments(src, end);
        if (isIdentStart(src[nameStart])) {
          let nameEnd = nameStart + 1;
          while (nameEnd < src.length && isIdentChar(src[nameEnd])) {
            nameEnd += 1;
          }
          if (src.slice(nameStart, nameEnd) === fnName) {
            let cursor = skipSpaceAndComments(src, nameEnd);
            let parenDepth = 0;
            while (cursor < src.length) {
              const s = skipTriviaOrLiteral(src, cursor);
              if (s !== -1) {
                cursor = s;
                continue;
              }
              const ch = src[cursor];
              if (ch === "(") {
                parenDepth += 1;
              } else if (ch === ")" && parenDepth > 0) {
                parenDepth -= 1;
              } else if (ch === "{" && parenDepth === 0) {
                const bodyEnd = findMatchingDelimiter(src, cursor, "{", "}");
                return src.slice(cursor + 1, bodyEnd);
              } else if (ch === ";" && parenDepth === 0) {
                break;
              }
              cursor += 1;
            }
          }
        }
      }
      i = end;
      continue;
    }

    i += 1;
  }

  throw new Error(`Function '${fnName}' not found in Rust source`);
}

/**
 * Split top-level comma-separated items inside a Rust argument list or struct literal.
 */
function splitTopLevelCommas(src) {
  const parts = [];
  let start = 0;
  let parenDepth = 0;
  let braceDepth = 0;
  let bracketDepth = 0;
  let i = 0;

  while (i < src.length) {
    const skipped = skipTriviaOrLiteral(src, i);
    if (skipped !== -1) {
      i = skipped;
      continue;
    }
    const ch = src[i];
    if (ch === "(") parenDepth += 1;
    else if (ch === ")" && parenDepth > 0) parenDepth -= 1;
    else if (ch === "{") braceDepth += 1;
    else if (ch === "}" && braceDepth > 0) braceDepth -= 1;
    else if (ch === "[") bracketDepth += 1;
    else if (ch === "]" && bracketDepth > 0) bracketDepth -= 1;
    else if (ch === "," && parenDepth === 0 && braceDepth === 0 && bracketDepth === 0) {
      const piece = stripSurroundingComments(src.slice(start, i));
      if (piece) parts.push(piece);
      start = i + 1;
    }
    i += 1;
  }

  const tail = stripSurroundingComments(src.slice(start));
  if (tail) parts.push(tail);
  return parts;
}

/**
 * Strip leading and trailing comments/whitespace from a Rust expression fragment.
 */
function stripSurroundingComments(expr) {
  const start = skipSpaceAndComments(expr, 0);
  let i = start;
  let lastContentEnd = start;
  while (i < expr.length) {
    const ch = expr[i];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      i += 1;
      continue;
    }
    if (ch === "/" && (expr[i + 1] === "/" || expr[i + 1] === "*")) {
      i = skipRustComment(expr, i);
      continue;
    }
    const str = readRustStringLiteral(expr, i);
    if (str) {
      i = str.nextPos;
      lastContentEnd = i;
      continue;
    }
    if (ch === "'") {
      i = skipRustCharLiteral(expr, i);
      lastContentEnd = i;
      continue;
    }
    i += 1;
    lastContentEnd = i;
  }
  return expr.slice(start, lastContentEnd);
}

/**
 * Parse a Rust string expression (`"..."`, `r#"..."#`, `"..." .to_string()`, `String::from(...)`, etc.).
 */
function parseRustStringExpr(rawExpr) {
  const expr = stripSurroundingComments(rawExpr);
  if (!expr) return null;

  for (const wrapper of ["String::from", "Cow::Borrowed"]) {
    if (expr.startsWith(wrapper)) {
      const parenPos = skipSpaceAndComments(expr, wrapper.length);
      if (expr[parenPos] === "(") {
        const closePos = findMatchingDelimiter(expr, parenPos, "(", ")");
        if (skipSpaceAndComments(expr, closePos + 1) === expr.length) {
          return parseRustStringExpr(expr.slice(parenPos + 1, closePos));
        }
      }
    }
  }

  const lit = readRustStringLiteral(expr, 0);
  if (!lit) return null;

  const rest = stripSurroundingComments(expr.slice(lit.nextPos));
  if (!rest) return lit.value;

  if (/^\.\s*(?:to_string|to_owned|into)\s*\(\s*\)$/.test(rest)) {
    return lit.value;
  }

  return null;
}

function parseRustScopeExpr(rawExpr) {
  const expr = stripSurroundingComments(rawExpr);
  const match = expr.match(/^PromptRewriteScope\s*::\s*(Prompt|All|Tools)$/);
  return match ? VALID_SCOPES[match[1]] : null;
}

function parseRustBoolExpr(rawExpr) {
  const expr = stripSurroundingComments(rawExpr);
  if (expr === "true") return true;
  if (expr === "false") return false;
  return null;
}

function parseStringField(rawExpr, entryIndex, fieldName) {
  let value;
  try {
    value = parseRustStringExpr(rawExpr);
  } catch {
    throw new Error(`PromptRewriteRule #${entryIndex}: invalid '${fieldName}' string literal`);
  }
  if (value === null) {
    throw new Error(`PromptRewriteRule #${entryIndex}: '${fieldName}' must be a string literal`);
  }
  return value;
}

function buildValidatedRule(id, pattern, replacement, scope, enabled, entryIndex, seenIds) {
  if (typeof id !== "string" || id.trim().length === 0) {
    throw new Error(`PromptRewriteRule #${entryIndex}: 'id' must not be empty`);
  }
  if (seenIds.has(id)) {
    throw new Error(`PromptRewriteRule #${entryIndex}: duplicate rule id`);
  }
  if (typeof pattern !== "string" || pattern.length === 0) {
    throw new Error(`PromptRewriteRule #${entryIndex}: 'pattern' must not be empty`);
  }
  if (pattern.length > MAX_PATTERN_CHARS) {
    throw new Error(
      `PromptRewriteRule #${entryIndex}: 'pattern' exceeds maximum length of ${MAX_PATTERN_CHARS} characters`,
    );
  }
  if (typeof replacement !== "string") {
    throw new Error(`PromptRewriteRule #${entryIndex}: 'replacement' must be a string literal`);
  }
  if (replacement.length > MAX_REPLACEMENT_CHARS) {
    throw new Error(
      `PromptRewriteRule #${entryIndex}: 'replacement' exceeds maximum length of ${MAX_REPLACEMENT_CHARS} characters`,
    );
  }
  if (scope !== "prompt" && scope !== "all" && scope !== "tools") {
    throw new Error(
      `PromptRewriteRule #${entryIndex}: 'scope' must be PromptRewriteScope::All, PromptRewriteScope::Prompt, or PromptRewriteScope::Tools`,
    );
  }
  if (typeof enabled !== "boolean") {
    throw new Error(`PromptRewriteRule #${entryIndex}: 'enabled' must be a boolean literal`);
  }
  seenIds.add(id);
  return { id, pattern, replacement, scope, enabled };
}

function parseWithScopeArgs(argBody, entryIndex, seenIds) {
  const args = splitTopLevelCommas(argBody);
  if (args.length !== 5) {
    throw new Error(
      `PromptRewriteRule #${entryIndex}: expected 5 arguments for with_scope, got ${args.length}`,
    );
  }
  const id = parseStringField(args[0], entryIndex, "id");
  const pattern = parseStringField(args[1], entryIndex, "pattern");
  const replacement = parseStringField(args[2], entryIndex, "replacement");
  const scope = parseRustScopeExpr(args[3]);
  if (scope === null) {
    throw new Error(
      `PromptRewriteRule #${entryIndex}: 'scope' must be PromptRewriteScope::All, PromptRewriteScope::Prompt, or PromptRewriteScope::Tools`,
    );
  }
  const enabled = parseRustBoolExpr(args[4]);
  if (enabled === null) {
    throw new Error(`PromptRewriteRule #${entryIndex}: 'enabled' must be a boolean literal`);
  }
  return buildValidatedRule(id, pattern, replacement, scope, enabled, entryIndex, seenIds);
}

function parseNewArgs(argBody, entryIndex, seenIds) {
  const args = splitTopLevelCommas(argBody);
  if (args.length !== 4) {
    throw new Error(
      `PromptRewriteRule #${entryIndex}: expected 4 arguments for new, got ${args.length}`,
    );
  }
  const id = parseStringField(args[0], entryIndex, "id");
  const pattern = parseStringField(args[1], entryIndex, "pattern");
  const replacement = parseStringField(args[2], entryIndex, "replacement");
  const enabled = parseRustBoolExpr(args[3]);
  if (enabled === null) {
    throw new Error(`PromptRewriteRule #${entryIndex}: 'enabled' must be a boolean literal`);
  }
  return buildValidatedRule(id, pattern, replacement, "all", enabled, entryIndex, seenIds);
}

const ALLOWED_STRUCT_FIELDS = new Set(["id", "pattern", "replacement", "scope", "enabled"]);

function parseStructLiteralFields(structBody, entryIndex, seenIds) {
  const fields = splitTopLevelCommas(structBody);
  const map = new Map();

  for (const field of fields) {
    const clean = stripSurroundingComments(field);
    if (!clean) continue;
    if (clean.startsWith("..")) {
      throw new Error(`PromptRewriteRule #${entryIndex}: unsupported struct update syntax`);
    }
    let keyEnd = 0;
    while (keyEnd < clean.length && isIdentChar(clean[keyEnd])) {
      keyEnd += 1;
    }
    const key = clean.slice(0, keyEnd);
    const colonPos = skipSpaceAndComments(clean, keyEnd);
    if (keyEnd === 0 || !isIdentStart(key[0]) || clean[colonPos] !== ":") {
      throw new Error(`PromptRewriteRule #${entryIndex}: invalid struct field syntax`);
    }
    if (!ALLOWED_STRUCT_FIELDS.has(key)) {
      throw new Error(`PromptRewriteRule #${entryIndex}: unsupported struct field`);
    }
    if (map.has(key)) {
      throw new Error(`PromptRewriteRule #${entryIndex}: duplicate struct field`);
    }
    map.set(key, clean.slice(colonPos + 1));
  }

  for (const required of ["id", "pattern", "replacement"]) {
    if (!map.has(required)) {
      throw new Error(`PromptRewriteRule #${entryIndex}: missing required field '${required}'`);
    }
  }

  const id = parseStringField(map.get("id"), entryIndex, "id");
  const pattern = parseStringField(map.get("pattern"), entryIndex, "pattern");
  const replacement = parseStringField(map.get("replacement"), entryIndex, "replacement");

  let scope = "all";
  if (map.has("scope")) {
    scope = parseRustScopeExpr(map.get("scope"));
    if (scope === null) {
      throw new Error(
        `PromptRewriteRule #${entryIndex}: 'scope' must be PromptRewriteScope::All, PromptRewriteScope::Prompt, or PromptRewriteScope::Tools`,
      );
    }
  }

  let enabled = true;
  if (map.has("enabled")) {
    enabled = parseRustBoolExpr(map.get("enabled"));
    if (enabled === null) {
      throw new Error(`PromptRewriteRule #${entryIndex}: 'enabled' must be a boolean literal`);
    }
  }

  return buildValidatedRule(id, pattern, replacement, scope, enabled, entryIndex, seenIds);
}

function extractVecMacroBody(fnBody) {
  let cursor = skipSpaceAndComments(fnBody, 0);
  if (
    fnBody.slice(cursor, cursor + 3) !== "vec" ||
    (cursor + 3 < fnBody.length && isIdentChar(fnBody[cursor + 3]))
  ) {
    throw new Error("recommended_preset_rules body must be a single vec![...] expression");
  }
  cursor = skipSpaceAndComments(fnBody, cursor + 3);
  if (fnBody[cursor] !== "!") {
    throw new Error("recommended_preset_rules body must be a single vec![...] expression");
  }
  cursor = skipSpaceAndComments(fnBody, cursor + 1);
  if (fnBody[cursor] !== "[") {
    throw new Error("recommended_preset_rules body must be a single vec![...] expression");
  }
  const closeBracket = findMatchingDelimiter(fnBody, cursor, "[", "]");
  if (skipSpaceAndComments(fnBody, closeBracket + 1) !== fnBody.length) {
    throw new Error("recommended_preset_rules body must be a single vec![...] expression");
  }
  return fnBody.slice(cursor + 1, closeBracket);
}

function parseRuleElement(rawElement, entryIndex, seenIds) {
  const expr = stripSurroundingComments(rawElement);
  let identEnd = 0;
  while (identEnd < expr.length && isIdentChar(expr[identEnd])) {
    identEnd += 1;
  }
  if (expr.slice(0, identEnd) !== "PromptRewriteRule") {
    throw new Error(`PromptRewriteRule #${entryIndex}: unrecognized rule element`);
  }

  const afterIdent = skipSpaceAndComments(expr, identEnd);

  if (expr.slice(afterIdent, afterIdent + 2) === "::") {
    const methodStart = skipSpaceAndComments(expr, afterIdent + 2);
    let methodEnd = methodStart;
    while (methodEnd < expr.length && isIdentChar(expr[methodEnd])) {
      methodEnd += 1;
    }
    const methodName = expr.slice(methodStart, methodEnd);
    if (methodName !== "with_scope" && methodName !== "new") {
      throw new Error(`PromptRewriteRule #${entryIndex}: unsupported associated function`);
    }
    const openParen = skipSpaceAndComments(expr, methodEnd);
    if (expr[openParen] !== "(") {
      throw new Error(`PromptRewriteRule #${entryIndex}: expected '(' after associated function`);
    }
    const closeParen = findMatchingDelimiter(expr, openParen, "(", ")");
    if (skipSpaceAndComments(expr, closeParen + 1) !== expr.length) {
      throw new Error(`PromptRewriteRule #${entryIndex}: unexpected trailing tokens in element`);
    }
    const argBody = expr.slice(openParen + 1, closeParen);
    return methodName === "with_scope"
      ? parseWithScopeArgs(argBody, entryIndex, seenIds)
      : parseNewArgs(argBody, entryIndex, seenIds);
  }

  if (expr[afterIdent] === "{") {
    const closeBrace = findMatchingDelimiter(expr, afterIdent, "{", "}");
    if (skipSpaceAndComments(expr, closeBrace + 1) !== expr.length) {
      throw new Error(`PromptRewriteRule #${entryIndex}: unexpected trailing tokens in element`);
    }
    return parseStructLiteralFields(expr.slice(afterIdent + 1, closeBrace), entryIndex, seenIds);
  }

  throw new Error(`PromptRewriteRule #${entryIndex}: unsupported syntax`);
}

/**
 * Parse `recommended_preset_rules()` from Rust source (`config.rs`) in strict mode.
 * Requires the function body to be a single `vec![...]` whose every top-level element
 * parses as `PromptRewriteRule::with_scope(...)`, `PromptRewriteRule::new(...)`,
 * or `PromptRewriteRule { ... }`. Throws on any unrecognized or invalid entry.
 */
export function parseRustPresetRules(rustSource) {
  if (typeof rustSource !== "string" || rustSource.length === 0) {
    throw new Error("Rust source must be a non-empty string");
  }

  const body = extractFunctionBody(rustSource, "recommended_preset_rules");
  const vecInner = extractVecMacroBody(body);
  const elements = splitTopLevelCommas(vecInner);

  if (elements.length === 0) {
    throw new Error("No valid PromptRewriteRule entries found in recommended_preset_rules");
  }

  const rules = [];
  const seenIds = new Set();
  for (let idx = 0; idx < elements.length; idx += 1) {
    const entryIndex = idx + 1;
    if (rules.length >= MAX_RULES) {
      throw new Error(`PromptRewriteRule #${entryIndex}: exceeds maximum of ${MAX_RULES} rules`);
    }
    rules.push(parseRuleElement(elements[idx], entryIndex, seenIds));
  }

  if (rules.length !== elements.length) {
    throw new Error("Parsed rule count does not match vec![] element count");
  }

  return rules;
}

async function readResponseTextWithLimit(res, signal, maxBytes = MAX_UPSTREAM_BODY_BYTES) {
  const rawLen = res.headers?.get?.("content-length");
  if (rawLen !== null && rawLen !== undefined && rawLen !== "") {
    const contentLength = Number(rawLen);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      await res.body?.cancel?.().catch(() => {});
      throw new Error(`Upstream response exceeds maximum size of ${maxBytes} bytes`);
    }
  }

  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    const onAbort = () => {
      reader.cancel(signal?.reason).catch(() => {});
    };
    if (signal) {
      if (signal.aborted) {
        onAbort();
      } else {
        signal.addEventListener("abort", onAbort, { once: true });
      }
    }

    const chunks = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            await reader.cancel().catch(() => {});
            throw new Error(`Upstream response exceeds maximum size of ${maxBytes} bytes`);
          }
          chunks.push(value);
        }
      }
    } finally {
      if (signal) {
        signal.removeEventListener("abort", onAbort);
      }
      reader.releaseLock?.();
    }

    const merged = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(merged);
  }

  const text = await res.text();
  if (Buffer.byteLength(text, "utf8") > maxBytes) {
    throw new Error(`Upstream response exceeds maximum size of ${maxBytes} bytes`);
  }
  return text;
}

/**
 * Fetch and parse the latest upstream preset rules from Antigravity-Manager (`beta` branch).
 */
export async function fetchUpstreamPresetRules(opts = {}) {
  const url = opts.url ?? UPSTREAM_AGT_BETA_CONFIG_URL;
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("No fetch implementation available");
  }

  const timeoutMs =
    typeof opts.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
      ? opts.timeoutMs
      : 12000;

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new Error(`Upstream fetch timed out after ${timeoutMs}ms`));
  }, timeoutMs);

  let onCallerAbort;
  if (opts.signal) {
    if (opts.signal.aborted) {
      clearTimeout(timer);
      controller.abort(opts.signal.reason);
    } else {
      onCallerAbort = () => controller.abort(opts.signal.reason);
      opts.signal.addEventListener("abort", onCallerAbort, { once: true });
    }
  }

  try {
    const res = await fetchImpl(url, {
      method: "GET",
      headers: {
        Accept: "text/plain",
        "User-Agent": "magpie-agy2api-plugin",
      },
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`Upstream HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ""}`);
    }

    const text = await readResponseTextWithLimit(res, controller.signal);
    const rules = parseRustPresetRules(text);
    return {
      ok: true,
      source: url,
      branch: "beta",
      fetchedAt: new Date().toISOString(),
      count: rules.length,
      rules,
    };
  } catch (err) {
    if (timedOut) {
      throw new Error(`Upstream fetch timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
    if (opts.signal && onCallerAbort) {
      opts.signal.removeEventListener("abort", onCallerAbort);
    }
  }
}

function sendResponse(res, status, contentType, body, extraHeaders = {}) {
  res.writeHead(status, {
    "Content-Type": contentType,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    // Magpie's servePageService runs pages inside `sandbox allow-scripts` (opaque Origin: null),
    // so browsers enforce CORS on same-service `fetch()` calls.
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type",
    ...extraHeaders,
  });
  res.end(body);
}

function sendJson(res, status, payload) {
  sendResponse(res, status, "application/json; charset=utf-8", JSON.stringify(payload));
}

function rewriteBridgeScriptTag(html) {
  return html.replace(
    /<script\s+src=["']_magpie\/bridge\.js["']\s*><\/script>/i,
    '<script src="service-bridge.js"></script>',
  );
}

function createRequestHandler(port, opts) {
  const uiDir = opts.uiDir ? path.resolve(opts.uiDir) : DEFAULT_UI_DIR;
  const cacheTtlMs =
    typeof opts.cacheTtlMs === "number" && Number.isFinite(opts.cacheTtlMs) && opts.cacheTtlMs >= 0
      ? opts.cacheTtlMs
      : UPSTREAM_CACHE_TTL_MS;

  let cachedResult = null;
  let inFlightUpstream = null;

  async function getUpstreamPresetsPayload() {
    const now = Date.now();
    if (cachedResult && now < cachedResult.expiresAt) {
      return cachedResult.payload;
    }
    cachedResult = null;

    if (!inFlightUpstream) {
      inFlightUpstream = fetchUpstreamPresetRules({
        url: opts.upstreamUrl,
        fetchImpl: opts.fetchImpl,
        timeoutMs: opts.timeoutMs,
      })
        .then((payload) => {
          if (cacheTtlMs > 0) {
            cachedResult = {
              payload,
              expiresAt: Date.now() + cacheTtlMs,
            };
          }
          return payload;
        })
        .finally(() => {
          inFlightUpstream = null;
        });
    }

    return inFlightUpstream;
  }

  return async (req, res) => {
    try {
      const method = (req.method || "GET").toUpperCase();
      const reqUrl = new URL(req.url || "/", `http://127.0.0.1:${port}`);
      const pathname = reqUrl.pathname;

      if (method === "OPTIONS") {
        return sendResponse(res, 204, "text/plain; charset=utf-8", "");
      }

      if (pathname === "/health") {
        if (method !== "GET") {
          return sendJson(res, 405, { ok: false, error: "Method not allowed" });
        }
        return sendJson(res, 200, { ok: true, port });
      }

      if (pathname === "/api/upstream-presets") {
        if (method !== "GET") {
          return sendJson(res, 405, { ok: false, error: "Method not allowed" });
        }
        try {
          const payload = await getUpstreamPresetsPayload();
          return sendJson(res, 200, payload);
        } catch (err) {
          return sendJson(res, 502, {
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }

      if (pathname === "/" || pathname === "/index.html" || pathname === "/sanitizer-panel.html") {
        if (method !== "GET") {
          return sendJson(res, 405, { ok: false, error: "Method not allowed" });
        }
        try {
          const rawHtml = await fs.readFile(path.join(uiDir, "sanitizer-panel.html"), "utf8");
          const html = rewriteBridgeScriptTag(rawHtml);
          return sendResponse(res, 200, "text/html; charset=utf-8", html, {
            "Content-Security-Policy": HTML_CSP,
          });
        } catch {
          return sendJson(res, 404, { ok: false, error: "Not found" });
        }
      }

      const staticAsset = STATIC_ROUTES[pathname];
      if (staticAsset) {
        if (method !== "GET") {
          return sendJson(res, 405, { ok: false, error: "Method not allowed" });
        }
        try {
          const content = await fs.readFile(path.join(uiDir, staticAsset.file));
          return sendResponse(res, 200, staticAsset.contentType, content);
        } catch {
          return sendJson(res, 404, { ok: false, error: "Not found" });
        }
      }

      return sendJson(res, 404, { ok: false, error: "Not found" });
    } catch (err) {
      if (!res.headersSent) {
        sendJson(res, 500, {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        });
      } else {
        res.end();
      }
    }
  };
}

async function closeOtherServices(registry, keepPort) {
  const closing = [];
  for (const [otherPort, otherEntry] of Array.from(registry.entries())) {
    if (otherPort !== keepPort) {
      closing.push(otherEntry.close());
    }
  }
  await Promise.allSettled(closing);
}

/**
 * Start (or reuse) the localhost page service on `127.0.0.1:<port>`.
 */
export async function startPageService(opts = {}) {
  const port = resolvePort(opts.port);
  const registry = getPageServiceRegistry();
  const pending = getPendingRegistry();

  while (pending.has(port)) {
    await pending.get(port);
  }

  const nextHandler = createRequestHandler(port, opts);

  const existing = registry.get(port);
  if (existing?.server?.listening) {
    existing.setHandler?.(nextHandler);
    await closeOtherServices(registry, port);
    return existing;
  }
  if (existing) {
    registry.delete(port);
  }

  const handlerRef = { current: nextHandler };

  const startupPromise = new Promise((resolve) => {
    const server = http.createServer((req, res) => handlerRef.current(req, res));

    let settled = false;

    const close = async () => {
      const current = registry.get(port);
      if (current?.server === server) {
        registry.delete(port);
      }
      if (!server.listening) return;
      server.closeAllConnections?.();
      await new Promise((done) => {
        server.close(() => done());
      });
    };

    server.on("error", (err) => {
      const current = registry.get(port);
      if (current?.server === server) {
        registry.delete(port);
      }
      if (!settled) {
        settled = true;
        pending.delete(port);
        resolve({
          ok: false,
          port,
          error: err instanceof Error ? err.message : String(err),
          server: null,
          close: async () => {},
        });
      }
    });

    server.listen(port, "127.0.0.1", async () => {
      server.unref?.();
      const entry = {
        ok: true,
        port,
        url: `http://127.0.0.1:${port}`,
        server,
        close,
        setHandler(fn) {
          handlerRef.current = fn;
        },
      };
      registry.set(port, entry);
      await closeOtherServices(registry, port);
      if (!settled) {
        settled = true;
        pending.delete(port);
        resolve(entry);
      }
    });
  });

  pending.set(port, startupPromise);
  return startupPromise;
}

/**
 * Stop the running localhost page service on `port`, or all running services if omitted.
 */
export async function stopPageService(port) {
  const registry = getPageServiceRegistry();
  const pending = getPendingRegistry();

  if (port !== undefined && port !== null) {
    const n = typeof port === "number" ? port : Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      return { ok: true, stoppedPorts: [] };
    }
    while (pending.has(n)) {
      await pending.get(n);
    }
    const entry = registry.get(n);
    if (!entry) {
      return { ok: true, stoppedPorts: [] };
    }
    await entry.close();
    return { ok: true, stoppedPorts: [n] };
  }

  while (pending.size > 0) {
    await Promise.allSettled(Array.from(pending.values()));
  }

  const entries = Array.from(registry.entries());
  await Promise.allSettled(entries.map(([, entry]) => entry.close()));
  return { ok: true, stoppedPorts: entries.map(([p]) => p) };
}
