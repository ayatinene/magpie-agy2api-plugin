/**
 * Shared entry for running the PromptSanitizer over one request body.
 *
 * Used from two places with the same plugin options:
 * - `middleware.mjs` (`onProvider`, Go `moejs`, 250 ms budget, agent API format)
 * - `lib/fetch.mjs` (provider `fetch`, Bun, no time limit, provider wire format)
 *
 * Magpie treats a middleware hook that runs out of time as absent and sends the
 * body as-is, so the provider `fetch` runs the same pass again. Sanitizing is
 * idempotent: a body the middleware already cleaned comes back unchanged.
 *
 * Pure ES2023, zero Node.js APIs, zero prompt logging.
 */

import {
  RECOMMENDED_PRESET_RULES,
  compilePromptRewriteRules,
  normalizeSideloadMode,
  sanitizePayload,
} from "./sanitizer.mjs";

const MAX_RULE_CACHE_ENTRIES = 32;
const compiledRulesCache = new Map();

function coerceBool(value, fallback) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const trimmed = value.trim().toLowerCase();
    if (trimmed === "false" || trimmed === "0" || trimmed === "off" || trimmed === "no") {
      return false;
    }
    if (trimmed === "true" || trimmed === "1" || trimmed === "on" || trimmed === "yes") {
      return true;
    }
  }
  return fallback;
}

function getCompiledRules(enabled, rules) {
  if (!enabled) {
    return [];
  }
  const useDefaultPreset = rules === RECOMMENDED_PRESET_RULES;
  const cacheKey = useDefaultPreset
    ? "__PRESET_DEFAULT__"
    : JSON.stringify(rules);

  const cached = compiledRulesCache.get(cacheKey);
  if (cached !== undefined) {
    return cached;
  }

  const compiled = compilePromptRewriteRules({ enabled: true, rules });
  if (compiledRulesCache.size >= MAX_RULE_CACHE_ENTRIES) {
    const oldestKey = compiledRulesCache.keys().next().value;
    if (oldestKey !== undefined) {
      compiledRulesCache.delete(oldestKey);
    }
  }
  compiledRulesCache.set(cacheKey, compiled);
  return compiled;
}

export function isPromptSanitizerEnabled(options) {
  if (options?.promptSanitizer === false || options?.prompt_sanitizer === false) {
    return false;
  }
  return coerceBool(options?.promptSanitizer ?? options?.prompt_sanitizer, true);
}

export function resolvePromptRewriteOptions(options) {
  const raw = options?.promptRewrite ?? options?.prompt_rewrite;
  const rw = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};

  const enabled = coerceBool(rw.enabled, true);
  const normalizeIdentity = coerceBool(
    rw.normalize_identity ?? rw.normalizeIdentity,
    true,
  );
  const sanitizeToolsDescription = coerceBool(
    rw.sanitize_tools_description ?? rw.sanitizeToolsDescription,
    true,
  );
  const sideloadMode = normalizeSideloadMode(rw.sideload_mode ?? rw.sideloadMode);
  const rules = Array.isArray(rw.rules) ? rw.rules : RECOMMENDED_PRESET_RULES;

  return {
    enabled,
    normalizeIdentity,
    sanitizeToolsDescription,
    sideloadMode,
    compiledRules: getCompiledRules(enabled, rules),
  };
}

/**
 * Returns the sanitized body, or `undefined` when the sanitizer is switched
 * off or nothing changed. `protocol` is `gemini` / `anthropic` / `chat` /
 * `responses`. Never mutates `body`.
 */
export function sanitizeRequestBody(protocol, body, options) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return undefined;
  }
  if (!isPromptSanitizerEnabled(options)) {
    return undefined;
  }
  const result = sanitizePayload(protocol, body, resolvePromptRewriteOptions(options));
  return result.changed ? result.body : undefined;
}
