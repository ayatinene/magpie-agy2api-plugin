/**
 * Magpie Gateway Middleware (`onProvider`) for Agy2API PromptSanitizer.
 *
 * Pure ES2023 module targeting Go `github.com/MoeForge/moejs v0.1.0`:
 * - Zero Node.js APIs, zero ctx cloning, zero prompt logging.
 * - Fail-open: unexpected errors return `undefined` (passthrough original body).
 *
 * Intentionally left to Agy2API:
 * - HTTP transport header handling
 * - Embedded `data:` media URL extraction and inlineData re-attachment
 */

import {
  RECOMMENDED_PRESET_RULES,
  compilePromptRewriteRules,
  normalizeSideloadMode,
  sanitizePayload,
} from "./lib/sanitizer.mjs";

export const DEFAULT_TARGET_PROVIDER_ID = "agy2api";

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

function resolvePromptRewriteOptions(options) {
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

export function onProvider(body, ctx) {
  try {
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return undefined;
    }

    const options = ctx?.options;
    const targetProviderId =
      (typeof options?.providerId === "string" && options.providerId.trim()) ||
      DEFAULT_TARGET_PROVIDER_ID;

    if (ctx?.provider?.id !== targetProviderId) {
      return undefined;
    }

    if (
      options?.promptSanitizer === false ||
      options?.prompt_sanitizer === false ||
      coerceBool(options?.promptSanitizer ?? options?.prompt_sanitizer, true) === false
    ) {
      return undefined;
    }

    const rewriteOpts = resolvePromptRewriteOptions(options);
    const result = sanitizePayload(ctx?.protocol, body, rewriteOpts);
    return result.changed ? result.body : undefined;
  } catch {
    return undefined;
  }
}
