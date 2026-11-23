import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const DEFAULT_PAGE_SERVICE_PORT = 18417;
export const UPSTREAM_AGT_BETA_CONFIG_URL =
  "https://raw.githubusercontent.com/lbjlaq/Antigravity-Manager/beta/src-tauri/src/proxy/config.rs";
export const MAX_RULES = 64;

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
      const piece = src.slice(start, i).trim();
      if (piece) parts.push(piece);
      start = i + 1;
    }
    i += 1;
  }

  const tail = src.slice(start).trim();
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
  const match = expr.match(/^(?:PromptRewriteScope\s*::\s*)?(Prompt|All|Tools)$/);
  return match ? VALID_SCOPES[match[1]] : null;
}

function parseRustBoolExpr(rawExpr) {
  const expr = stripSurroundingComments(rawExpr);
  if (expr === "true") return true;
  if (expr === "false") return false;
  return null;
}

function buildValidatedRule(id, pattern, replacement, scope, enabled) {
  if (typeof id !== "string" || id.trim().length === 0) return null;
  if (typeof pattern !== "string" || pattern.length === 0) return null;
  if (typeof replacement !== "string") return null;
  if (scope !== "prompt" && scope !== "all" && scope !== "tools") return null;
  if (typeof enabled !== "boolean") return null;
  return { id, pattern, replacement, scope, enabled };
}

function parseWithScopeArgs(argBody) {
  const args = splitTopLevelCommas(argBody);
  if (args.length !== 5) return null;
  const id = parseRustStringExpr(args[0]);
  const pattern = parseRustStringExpr(args[1]);
  const replacement = parseRustStringExpr(args[2]);
  const scope = parseRustScopeExpr(args[3]);
  const enabled = parseRustBoolExpr(args[4]);
  return buildValidatedRule(id, pattern, replacement, scope, enabled);
}

function parseStructLiteralFields(structBody) {
  const fields = splitTopLevelCommas(structBody);
  const map = new Map();

  for (const field of fields) {
    const clean = stripSurroundingComments(field);
    if (!clean || clean.startsWith("..")) continue;
    const colonIdx = clean.indexOf(":");
    if (colonIdx === -1) continue;
    const key = clean.slice(0, colonIdx).trim();
    const val = clean.slice(colonIdx + 1);
    map.set(key, val);
  }

  if (!map.has("id") || !map.has("pattern") || !map.has("replacement")) {
    return null;
  }

  const id = parseRustStringExpr(map.get("id"));
  const pattern = parseRustStringExpr(map.get("pattern"));
  const replacement = parseRustStringExpr(map.get("replacement"));
  const scope = map.has("scope") ? parseRustScopeExpr(map.get("scope")) : "prompt";
  const enabled = map.has("enabled") ? parseRustBoolExpr(map.get("enabled")) : true;
  return buildValidatedRule(id, pattern, replacement, scope, enabled);
}

/**
 * Parse `recommended_preset_rules()` from Rust source (`config.rs`).
 * Supports both `PromptRewriteRule::with_scope(...)` and `PromptRewriteRule { ... }`.
 */
export function parseRustPresetRules(rustSource) {
  if (typeof rustSource !== "string" || rustSource.length === 0) {
    throw new Error("Rust source must be a non-empty string");
  }

  const body = extractFunctionBody(rustSource, "recommended_preset_rules");
  const rules = [];
  let i = 0;

  while (i < body.length && rules.length < MAX_RULES) {
    const skipped = skipTriviaOrLiteral(body, i);
    if (skipped !== -1) {
      i = skipped;
      continue;
    }

    if (isIdentStart(body[i])) {
      let end = i + 1;
      while (end < body.length && isIdentChar(body[end])) {
        end += 1;
      }
      if (body.slice(i, end) === "PromptRewriteRule") {
        const afterIdent = skipSpaceAndComments(body, end);

        if (body.slice(afterIdent, afterIdent + 2) === "::") {
          const methodStart = skipSpaceAndComments(body, afterIdent + 2);
          let methodEnd = methodStart;
          while (methodEnd < body.length && isIdentChar(body[methodEnd])) {
            methodEnd += 1;
          }
          if (body.slice(methodStart, methodEnd) === "with_scope") {
            const openParen = skipSpaceAndComments(body, methodEnd);
            if (body[openParen] === "(") {
              const closeParen = findMatchingDelimiter(body, openParen, "(", ")");
              const rule = parseWithScopeArgs(body.slice(openParen + 1, closeParen));
              if (rule) rules.push(rule);
              i = closeParen + 1;
              continue;
            }
          }
        } else if (body[afterIdent] === "{") {
          const closeBrace = findMatchingDelimiter(body, afterIdent, "{", "}");
          const rule = parseStructLiteralFields(body.slice(afterIdent + 1, closeBrace));
          if (rule) rules.push(rule);
          i = closeBrace + 1;
          continue;
        }
      }
      i = end;
      continue;
    }

    i += 1;
  }

  if (rules.length === 0) {
    throw new Error("No valid PromptRewriteRule entries found in recommended_preset_rules");
  }

  return rules;
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

    const text = await res.text();
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

/**
 * Start (or reuse) the localhost page service on `127.0.0.1:<port>`.
 */
export async function startPageService(opts = {}) {
  const port = resolvePort(opts.port);
  const registry = getPageServiceRegistry();
  const pending = getPendingRegistry();

  const existing = registry.get(port);
  if (existing?.server?.listening) {
    return existing;
  }
  if (existing) {
    registry.delete(port);
  }

  const inFlight = pending.get(port);
  if (inFlight) {
    return inFlight;
  }

  const uiDir = opts.uiDir ? path.resolve(opts.uiDir) : DEFAULT_UI_DIR;

  const startupPromise = new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
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
          if (method !== "GET" && method !== "POST") {
            return sendJson(res, 405, { ok: false, error: "Method not allowed" });
          }
          try {
            const payload = await fetchUpstreamPresetRules({
              url: opts.upstreamUrl,
              fetchImpl: opts.fetchImpl,
              timeoutMs: opts.timeoutMs,
            });
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
    });

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

    server.listen(port, "127.0.0.1", () => {
      server.unref?.();
      const entry = {
        ok: true,
        port,
        url: `http://127.0.0.1:${port}`,
        server,
        close,
      };
      registry.set(port, entry);
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
