import crypto from "node:crypto";
import { normalizeBaseUrl, resolveAuth } from "./auth.mjs";
import {
  clearAuxRouterState,
  commitMainSessionFromFetch,
  computePostRelayRequestDigest,
  consumeAuxIsolationTicket,
  extractConversationSnapshot,
  markTicketUpstreamExecuted,
  stripModelPrefix,
} from "./aux-router.mjs";
import {
  ensureModelsDiscovered,
  foldModelId,
  getDiscoveredModels,
  getModelMetadataMap,
  isXhighGeminiModel,
} from "./models.mjs";
import { RELAY_FIELD } from "./relay-crypto.mjs";
import { sanitizeRequestBody } from "./sanitize-request.mjs";

const DEFAULT_CACHE_AFFINITY_TTL_MS = 10 * 60 * 1000;
const DEFAULT_CACHE_AFFINITY_MIN_BODY_BYTES = 32 * 1024;
const DEFAULT_CACHE_AFFINITY_MAX_AUX_OUTPUT_TOKENS = 8192;
const MAX_PREFIX_CACHE_ENTRIES = 256;

const EFFORT_RANK = {
  minimal: 0,
  low: 1,
  medium: 2,
  high: 3,
  xhigh: 4,
  max: 5,
};

const EFFORT_TO_BUDGET = {
  minimal: 512,
  low: 1024,
  medium: 8192,
  high: 16384,
  xhigh: 24576,
  max: 32768,
};

const LOCKED_MODEL_SUFFIX_RE = /-(minimal|low|medium|high|xhigh|max|tiered|extra-low)$/i;

const prefixEffortCache = new Map();
const inFlightWarmKeys = new Map();
let nextWarmSeq = 0;
let cacheGeneration = 0;

export function clearPrefixEffortCache() {
  prefixEffortCache.clear();
  inFlightWarmKeys.clear();
  nextWarmSeq = 0;
  cacheGeneration++;
  clearAuxRouterState();
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function isPlainObject(val) {
  return Boolean(val) && typeof val === "object" && !Array.isArray(val);
}

function normalizeEffort(raw) {
  if (typeof raw !== "string") return null;
  const norm = raw.trim().toLowerCase().replace(/^thinking_level_/, "");
  if (norm === "none") return "none";
  return Object.prototype.hasOwnProperty.call(EFFORT_RANK, norm) ? norm : null;
}

function budgetTokensToEffort(budgetTokens) {
  if (typeof budgetTokens !== "number" || !Number.isFinite(budgetTokens)) return null;
  if (budgetTokens < 0) return null;
  if (budgetTokens === 0) return "none";
  if (budgetTokens <= 1024) return "low";
  if (budgetTokens <= 8192) return "medium";
  if (budgetTokens <= 16384) return "high";
  return "xhigh";
}

function cloneJson(value) {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value));
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => (item === undefined ? "null" : stableStringify(item))).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  const parts = [];
  for (const k of keys) {
    const v = value[k];
    if (v === undefined) continue;
    parts.push(`${JSON.stringify(k)}:${stableStringify(v)}`);
  }
  return `{${parts.join(",")}}`;
}

function extractLeadingSystemAndFirstMessage(items) {
  const leadingSystem = [];
  let firstUserOrMsg = null;
  let seenNonSystem = false;
  for (const item of items) {
    const role = String(item?.role || "").trim().toLowerCase();
    if (!seenNonSystem && (role === "system" || role === "developer")) {
      leadingSystem.push(item);
    } else {
      seenNonSystem = true;
      if (firstUserOrMsg === null) {
        firstUserOrMsg = item;
        break;
      }
    }
  }
  if (firstUserOrMsg === null && leadingSystem.length > 0) {
    firstUserOrMsg = leadingSystem[0];
  }
  return { leadingSystem, firstUserOrMsg };
}

function computePrefixKey(
  baseUrl,
  apiKeyDigest,
  sessionToken,
  protocol,
  requestedModel,
  parsedBody,
) {
  if (!parsedBody || !requestedModel) return null;
  const cleanModel = String(requestedModel).trim().replace(/^models\//, "");
  if (!cleanModel || LOCKED_MODEL_SUFFIX_RE.test(cleanModel)) return null;

  if (protocol === "gemini") {
    if (!Array.isArray(parsedBody.contents) || parsedBody.contents.length < 1) {
      return null;
    }
    const payload = stableStringify([
      baseUrl,
      apiKeyDigest,
      sessionToken,
      "gemini",
      cleanModel,
      parsedBody.tools ?? null,
      parsedBody.toolConfig ?? parsedBody.tool_config ?? null,
      parsedBody.cachedContent ?? parsedBody.cached_content ?? null,
      parsedBody.systemInstruction ?? null,
      parsedBody.contents[0],
    ]);
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  if (protocol === "anthropic") {
    if (!Array.isArray(parsedBody.messages) || parsedBody.messages.length < 1) {
      return null;
    }
    const payload = stableStringify([
      baseUrl,
      apiKeyDigest,
      sessionToken,
      "anthropic",
      cleanModel,
      parsedBody.tools ?? null,
      parsedBody.tool_choice ?? null,
      parsedBody.system ?? null,
      parsedBody.messages[0],
    ]);
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  if (protocol === "chat") {
    if (!Array.isArray(parsedBody.messages) || parsedBody.messages.length < 1) {
      return null;
    }
    const { leadingSystem, firstUserOrMsg } = extractLeadingSystemAndFirstMessage(
      parsedBody.messages,
    );
    const payload = stableStringify([
      baseUrl,
      apiKeyDigest,
      sessionToken,
      "chat",
      cleanModel,
      parsedBody.tools ?? null,
      parsedBody.tool_choice ?? null,
      parsedBody.functions ?? null,
      parsedBody.function_call ?? null,
      leadingSystem,
      firstUserOrMsg,
    ]);
    return crypto.createHash("sha256").update(payload).digest("hex");
  }

  if (protocol === "responses") {
    if (typeof parsedBody.input === "string") {
      const payload = stableStringify([
        baseUrl,
        apiKeyDigest,
        sessionToken,
        "responses",
        cleanModel,
        parsedBody.tools ?? null,
        parsedBody.tool_choice ?? null,
        parsedBody.instructions ?? null,
        parsedBody.input,
      ]);
      return crypto.createHash("sha256").update(payload).digest("hex");
    }
    if (Array.isArray(parsedBody.input) && parsedBody.input.length >= 1) {
      const { leadingSystem, firstUserOrMsg } = extractLeadingSystemAndFirstMessage(
        parsedBody.input,
      );
      const payload = stableStringify([
        baseUrl,
        apiKeyDigest,
        sessionToken,
        "responses",
        cleanModel,
        parsedBody.tools ?? null,
        parsedBody.tool_choice ?? null,
        [parsedBody.instructions ?? null, leadingSystem],
        firstUserOrMsg,
      ]);
      return crypto.createHash("sha256").update(payload).digest("hex");
    }
    return null;
  }

  return null;
}

function resolveEffectiveVariant(effort, thinkingLevels) {
  if (!effort) return null;
  let eff = String(effort).trim().toLowerCase();
  if (eff === "minimal") eff = "low";
  if (eff === "max") eff = "xhigh";
  if (eff === "xhigh" && Array.isArray(thinkingLevels) && !thinkingLevels.includes("xhigh")) {
    eff = "high";
  }
  return eff;
}

function resolveModelEffortMetadata(authScope, requestedModel) {
  const metaMap = getModelMetadataMap(authScope);
  const clean = String(requestedModel || "").trim().replace(/^models\//, "");
  const meta = metaMap.get(clean) ?? null;
  if (!meta) return { skip: false, thinkingLevels: null };
  if (meta.isAliasFixed) return { skip: true, thinkingLevels: null };
  const targetId = meta.aliasTarget
    ? String(meta.aliasTarget).trim().replace(/^models\//, "")
    : "";
  if (
    targetId &&
    (LOCKED_MODEL_SUFFIX_RE.test(targetId) || foldModelId(targetId).variant !== null)
  ) {
    return { skip: true, thinkingLevels: null };
  }
  const targetMeta = targetId ? metaMap.get(targetId) ?? null : null;
  const levels = Array.isArray(targetMeta?.thinkingLevels)
    ? targetMeta.thinkingLevels
    : Array.isArray(meta.thinkingLevels)
      ? meta.thinkingLevels
      : null;
  if (Array.isArray(levels) && levels.length <= 1) {
    return { skip: true, thinkingLevels: levels };
  }
  return { skip: false, thinkingLevels: levels };
}

function firstPositiveInt(...candidates) {
  for (const val of candidates) {
    if (typeof val === "number" && Number.isFinite(val) && val > 0) {
      return val;
    }
  }
  return null;
}

function resolveRequestEffortAndMaxOutput(protocol, parsedBody, headerEffort) {
  const hdrEffort = normalizeEffort(headerEffort);

  if (protocol === "gemini") {
    const genCfg = isPlainObject(parsedBody.generationConfig)
      ? parsedBody.generationConfig
      : isPlainObject(parsedBody.generation_config)
        ? parsedBody.generation_config
        : null;
    const tc = isPlainObject(genCfg?.thinkingConfig)
      ? genCfg.thinkingConfig
      : isPlainObject(genCfg?.thinking_config)
        ? genCfg.thinking_config
        : null;
    const rawLevel = tc?.thinkingLevel ?? tc?.thinking_level;
    const levelEffort = normalizeEffort(rawLevel);
    const rawBudget = tc?.thinkingBudget ?? tc?.thinking_budget;
    const maxOutputTokens = firstPositiveInt(
      genCfg?.maxOutputTokens,
      genCfg?.max_output_tokens,
    );

    if (levelEffort === "none" || rawBudget === 0) {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    if (levelEffort !== null) {
      return {
        effort: levelEffort,
        rank: EFFORT_RANK[levelEffort],
        maxOutputTokens,
        disabled: false,
        slot: "level",
        budgetTokens: null,
      };
    }
    if (typeof rawBudget === "number" && Number.isFinite(rawBudget)) {
      const bEffort = budgetTokensToEffort(rawBudget);
      return {
        effort: bEffort,
        rank: bEffort !== null ? EFFORT_RANK[bEffort] : null,
        maxOutputTokens,
        disabled: false,
        slot: "budget",
        budgetTokens: rawBudget,
      };
    }
    if (hdrEffort === "none") {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    return {
      effort: hdrEffort,
      rank: hdrEffort !== null ? EFFORT_RANK[hdrEffort] : null,
      maxOutputTokens,
      disabled: false,
      slot: hdrEffort !== null ? "header" : null,
      budgetTokens: null,
    };
  }

  if (protocol === "anthropic") {
    const maxOutputTokens = firstPositiveInt(parsedBody.max_tokens);
    if (
      Array.isArray(parsedBody.messages) &&
      parsedBody.messages.some((m) => m && typeof m === "object" && m.output_config !== undefined)
    ) {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    if (
      isPlainObject(parsedBody.thinking) &&
      (parsedBody.thinking.type === "disabled" || parsedBody.thinking.type === "between_tools")
    ) {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    const outputEffort = normalizeEffort(parsedBody.output_config?.effort);
    if (outputEffort === "none") {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    if (outputEffort !== null) {
      return {
        effort: outputEffort,
        rank: EFFORT_RANK[outputEffort],
        maxOutputTokens,
        disabled: false,
        slot: "output_config",
        budgetTokens: null,
      };
    }
    if (
      isPlainObject(parsedBody.thinking) &&
      parsedBody.thinking.type === "enabled" &&
      typeof parsedBody.thinking.budget_tokens === "number" &&
      Number.isFinite(parsedBody.thinking.budget_tokens)
    ) {
      const bt = parsedBody.thinking.budget_tokens;
      if (bt === 0) {
        return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: 0 };
      }
      const bEffort = budgetTokensToEffort(bt);
      return {
        effort: bEffort,
        rank: bEffort !== null ? EFFORT_RANK[bEffort] : null,
        maxOutputTokens,
        disabled: false,
        slot: "budget",
        budgetTokens: bt,
      };
    }
    if (hdrEffort === "none") {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    return {
      effort: hdrEffort,
      rank: hdrEffort !== null ? EFFORT_RANK[hdrEffort] : null,
      maxOutputTokens,
      disabled: false,
      slot: hdrEffort !== null ? "header" : null,
      budgetTokens: null,
    };
  }

  if (protocol === "chat") {
    const maxOutputTokens = firstPositiveInt(
      parsedBody.max_completion_tokens,
      parsedBody.max_tokens,
    );
    const extraThinking = parsedBody.extra_body?.google?.thinking_config;
    const extraLevel = normalizeEffort(extraThinking?.thinking_level);
    const extraBudget = extraThinking?.thinking_budget;
    const reEffort = normalizeEffort(parsedBody.reasoning_effort);
    const roEffort = normalizeEffort(parsedBody.reasoning?.effort);
    if (
      extraLevel === "none" ||
      extraBudget === 0 ||
      roEffort === "none" ||
      reEffort === "none"
    ) {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    if (extraLevel !== null || (typeof extraBudget === "number" && Number.isFinite(extraBudget))) {
      // Nested extra_body.google.thinking_config overrides top-level fields; conservatively skip rewriting
      const e = extraLevel ?? budgetTokensToEffort(extraBudget);
      return {
        effort: e,
        rank: e !== null ? EFFORT_RANK[e] : null,
        maxOutputTokens,
        disabled: false,
        slot: null,
        budgetTokens: extraLevel === null ? extraBudget : null,
      };
    }
    if (roEffort !== null) {
      return {
        effort: roEffort,
        rank: EFFORT_RANK[roEffort],
        maxOutputTokens,
        disabled: false,
        slot: "reasoning",
        budgetTokens: null,
      };
    }
    if (reEffort !== null) {
      return {
        effort: reEffort,
        rank: EFFORT_RANK[reEffort],
        maxOutputTokens,
        disabled: false,
        slot: "reasoning_effort",
        budgetTokens: null,
      };
    }
    if (hdrEffort === "none") {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    return {
      effort: hdrEffort,
      rank: hdrEffort !== null ? EFFORT_RANK[hdrEffort] : null,
      maxOutputTokens,
      disabled: false,
      slot: hdrEffort !== null ? "header" : null,
      budgetTokens: null,
    };
  }

  if (protocol === "responses") {
    const maxOutputTokens = firstPositiveInt(
      parsedBody.max_output_tokens,
      parsedBody.max_tokens,
    );
    if (
      Array.isArray(parsedBody.input) &&
      parsedBody.input.some((item) => item && typeof item === "object" && item.type === "configuration_update")
    ) {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    const roEffort = normalizeEffort(parsedBody.reasoning?.effort);
    if (roEffort === "none") {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    if (roEffort !== null) {
      return {
        effort: roEffort,
        rank: EFFORT_RANK[roEffort],
        maxOutputTokens,
        disabled: false,
        slot: "reasoning",
        budgetTokens: null,
      };
    }
    if (hdrEffort === "none") {
      return { effort: null, rank: null, maxOutputTokens, disabled: true, slot: null, budgetTokens: null };
    }
    return {
      effort: hdrEffort,
      rank: hdrEffort !== null ? EFFORT_RANK[hdrEffort] : null,
      maxOutputTokens,
      disabled: false,
      slot: hdrEffort !== null ? "header" : null,
      budgetTokens: null,
    };
  }

  return { effort: null, rank: null, maxOutputTokens: null, disabled: false, slot: null, budgetTokens: null };
}

function getFreshWarmEntry(prefixKey, now, ttlMs) {
  if (!prefixKey) return null;
  const entry = prefixEffortCache.get(prefixKey);
  if (!entry) return null;
  if (now - entry.updatedAt > ttlMs) {
    prefixEffortCache.delete(prefixKey);
    return null;
  }
  prefixEffortCache.delete(prefixKey);
  prefixEffortCache.set(prefixKey, entry);
  return entry;
}

function saveWarmEntry(prefixKey, entry, now, ttlMs) {
  if (!prefixKey) return;
  const existing = prefixEffortCache.get(prefixKey);
  if (
    existing &&
    typeof existing.seq === "number" &&
    typeof entry.seq === "number" &&
    existing.seq > entry.seq
  ) {
    return;
  }
  if (existing) {
    prefixEffortCache.delete(prefixKey);
  }
  if (prefixEffortCache.size >= MAX_PREFIX_CACHE_ENTRIES) {
    for (const [k, v] of prefixEffortCache.entries()) {
      if (now - v.updatedAt > ttlMs) {
        prefixEffortCache.delete(k);
      }
    }
    while (prefixEffortCache.size >= MAX_PREFIX_CACHE_ENTRIES) {
      const oldestKey = prefixEffortCache.keys().next().value;
      if (oldestKey === undefined) break;
      prefixEffortCache.delete(oldestKey);
    }
  }
  prefixEffortCache.set(prefixKey, entry);
}

function stripRootPrefix(pathname, baseUrl) {
  const cleanPath = pathname || "/";
  if (!baseUrl) return cleanPath;
  try {
    const rp = new URL(normalizeBaseUrl(baseUrl)).pathname.replace(/\/+$/, "");
    if (rp) {
      if (cleanPath === rp) return "/";
      if (cleanPath.startsWith(`${rp}/`)) {
        return cleanPath.slice(rp.length) || "/";
      }
    }
  } catch {
    // ignore invalid baseUrl
  }
  return cleanPath;
}

function splitVersionPrefix(relPath) {
  const m = relPath.match(/^\/(v1beta|v1)(?=\/|$)/i);
  if (!m) return { version: "", rest: relPath };
  const rest = relPath.slice(m[0].length) || "/";
  return { version: m[1].toLowerCase(), rest };
}

function isGeminiAuthRequest(headers, searchParams) {
  const hasAuth = Boolean(headers?.get?.("authorization")?.trim());
  if (hasAuth) return false;
  const hasGoogHeader = Boolean(headers?.get?.("x-goog-api-key")?.trim());
  const hasKeyQuery = Boolean(searchParams?.has?.("key"));
  return hasGoogHeader || hasKeyQuery;
}

export function detectProtocol(pathname, baseUrl, headers, searchParams) {
  const relPath = stripRootPrefix(pathname, baseUrl);
  const { version, rest } = splitVersionPrefix(relPath);

  if (/^\/chat\/completions\/?$/.test(rest)) {
    return "chat";
  }
  if (/^\/responses(?:\/.*)?$/.test(rest)) {
    return "responses";
  }
  if (/^\/messages(?:\/count_tokens)?\/?$/.test(rest)) {
    return "anthropic";
  }
  if (/^\/models\/[^/]+:(?:generateContent|streamGenerateContent|countTokens)$/.test(rest)) {
    return "gemini";
  }
  if (/^\/models(?:\/.*)?$/.test(rest)) {
    if (version === "v1beta") return "gemini";
    return isGeminiAuthRequest(headers, searchParams) ? "gemini" : "other";
  }
  return "other";
}

function isGenerationEndpoint(protocol, versionlessPath, method) {
  if (String(method || "POST").toUpperCase() !== "POST") return false;
  if (protocol === "chat") return /^\/chat\/completions\/?$/.test(versionlessPath);
  if (protocol === "responses") return /^\/responses\/?$/.test(versionlessPath);
  if (protocol === "anthropic") return /^\/messages\/?$/.test(versionlessPath);
  if (protocol === "gemini") {
    return /^\/models\/[^/]+:(?:generateContent|streamGenerateContent)$/.test(versionlessPath);
  }
  return false;
}

function isSessionPartitionEndpoint(protocol, versionlessPath, method) {
  if (isGenerationEndpoint(protocol, versionlessPath, method)) return true;
  if (String(method || "POST").toUpperCase() !== "POST") return false;
  if (protocol === "anthropic") {
    return /^\/messages\/count_tokens\/?$/.test(versionlessPath);
  }
  if (protocol === "gemini") {
    return /^\/models\/[^/]+:countTokens$/.test(versionlessPath);
  }
  return false;
}

export function extractGeminiModelFromPath(pathname) {
  const m =
    pathname.match(/\/models\/([^/:?#]+):(?:generateContent|streamGenerateContent|countTokens)$/i) ||
    pathname.match(/\/models\/([^/:?#]+)/i);
  if (!m) return "";
  try {
    return decodeURIComponent(m[1]).trim();
  } catch {
    return m[1].trim();
  }
}

export function rewriteUpstreamUrl(rawUrl, baseUrl, headers, stripBaseUrl) {
  const root = normalizeBaseUrl(baseUrl);
  const parsed = new URL(rawUrl, root);
  const stripRoot = stripBaseUrl ? normalizeBaseUrl(stripBaseUrl) : root;
  const relPath = stripRootPrefix(parsed.pathname, stripRoot);
  const { rest } = splitVersionPrefix(relPath);
  const protocol = detectProtocol(parsed.pathname, stripRoot, headers, parsed.searchParams);

  if (protocol === "gemini") {
    return {
      protocol,
      url: `${root}/v1beta${rest}${parsed.search}`,
    };
  }

  if (protocol === "anthropic" || protocol === "chat" || protocol === "responses") {
    return {
      protocol,
      url: `${root}/v1${rest}${parsed.search}`,
    };
  }

  return {
    protocol,
    url: `${root}${relPath}${parsed.search}`,
  };
}

function decodeBodyText(body) {
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array || Buffer.isBuffer(body)) {
    return new TextDecoder("utf-8").decode(body);
  }
  return null;
}

export function hasWholeModelToken(text, model) {
  if (!model || typeof text !== "string") return false;
  const escaped = model.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`(?:^|[^A-Za-z0-9._-])${escaped}(?:$|[^A-Za-z0-9._-])`);
  return re.test(text);
}

function tryParseJsonObject(rawText) {
  try {
    const candidate = JSON.parse(rawText);
    if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
      return candidate;
    }
  } catch {
    // ignore
  }
  return null;
}

function hasDetailReason(errObj, ...reasons) {
  if (!Array.isArray(errObj?.details)) return false;
  return errObj.details.some(
    (d) => d && typeof d === "object" && reasons.includes(d.reason),
  );
}

function prependModelPrefix(errObj, model) {
  const base = String(errObj.message ?? "").trim();
  let changed = false;
  const next = { ...errObj };
  if (model && !hasWholeModelToken(base, model)) {
    next.message = base ? `model ${model}: ${base}` : `model ${model}`;
    changed = true;
  }
  if (model && !next.model) {
    next.model = model;
    changed = true;
  }
  return { next, changed };
}

export function normalizeUpstreamErrorResponse(rawText, status, requestedModel, opts = {}) {
  const model = typeof requestedModel === "string" ? requestedModel.trim() : "";
  const parsed = tryParseJsonObject(rawText);
  if (!parsed || !isPlainObject(parsed.error)) {
    return null;
  }
  const errObj = parsed.error;

  if (status === 400) {
    const msgStr = typeof errObj.message === "string" ? errObj.message : "";
    if (
      hasDetailReason(errObj, "API_KEY_INVALID") &&
      !/^\s*(?:Authentication failed:\s*)?upstream\b/i.test(msgStr)
    ) {
      return {
        headers: { "x-magpie-sign-in": "expired" },
      };
    }

    const isContentMessage =
      /^\s*Upstream rejected the request content\b/i.test(msgStr) ||
      /^\s*Upstream rejected the input:\s*(?:SAFETY|BLOCKLIST|PROHIBITED_CONTENT)(?:\s*:|$)/i.test(
        msgStr,
      );

    if (parsed.type === "error" && typeof errObj.type === "string") {
      if (errObj.type !== "invalid_request_error" || !isContentMessage || errObj.code) {
        return null;
      }
      return {
        body: JSON.stringify({
          ...parsed,
          error: { ...errObj, code: "content_policy_violation" },
        }),
        contentType: "application/json",
      };
    }

    if (typeof errObj.code === "number") {
      if (errObj.status !== "INVALID_ARGUMENT" || !isContentMessage || errObj.type) {
        return null;
      }
      return {
        body: JSON.stringify({
          ...parsed,
          error: { ...errObj, type: "content_policy_violation" },
        }),
        contentType: "application/json",
      };
    }

    if (errObj.code === "invalid_prompt") {
      const origMsg = msgStr.trim();
      if (/flagged/i.test(origMsg)) {
        return null;
      }
      const nextMsg = `${origMsg || "Upstream rejected the request content"} (flagged by upstream content policy)`;
      return {
        body: JSON.stringify({
          ...parsed,
          error: { ...errObj, code: "invalid_prompt", message: nextMsg },
        }),
        contentType: "application/json",
      };
    }

    return null;
  }

  if (status === 401) {
    const msgStr = typeof errObj.message === "string" ? errObj.message : "";
    if (/^\s*(?:Authentication failed:\s*)?upstream 401\b/i.test(msgStr)) {
      return { headers: { "x-magpie-sign-in": "kept" } };
    }
    if (errObj.code === "invalid_api_key" || msgStr.trim() === "Invalid API Key") {
      return { headers: { "x-magpie-sign-in": "expired" } };
    }
    return { headers: { "x-magpie-sign-in": "kept" } };
  }

  if (status === 404) {
    if (!model || opts?.isModelEndpoint === false) {
      return null;
    }
    const msgStr = typeof errObj.message === "string" ? errObj.message : "";
    const isModelNotFound =
      /^\s*Model\s+\S+\s+is not in the account catalog\b/i.test(msgStr) ||
      errObj.code === "model_not_found" ||
      /upstream 404\b.*\bNOT_FOUND\b/i.test(msgStr);
    if (!isModelNotFound) {
      return null;
    }
    const origMsg = msgStr.trim();
    const alreadyNamed = hasWholeModelToken(origMsg, model) && /\bnot found\b/i.test(origMsg);
    const next = { ...errObj };
    let changed = false;
    if (!alreadyNamed) {
      next.message = origMsg ? `model ${model} not found: ${origMsg}` : `model ${model} not found`;
      changed = true;
    }
    if (!next.model) {
      next.model = model;
      changed = true;
    }
    if (!changed) return null;
    return {
      body: JSON.stringify({ ...parsed, error: next }),
      contentType: "application/json",
    };
  }

  if (status === 429) {
    const msgStr = typeof errObj.message === "string" ? errObj.message : "";
    if (
      /^\s*(?:no account can serve|no ready accounts)\b/i.test(msgStr) ||
      /^\s*no available accounts\s*$/i.test(msgStr)
    ) {
      return null;
    }
    const isCooldownOrRateLimit =
      /\bAll accounts for model\b|\bNo available accounts for model\b/i.test(msgStr) ||
      hasDetailReason(errObj, "QUOTA_EXHAUSTED", "INSUFFICIENT_G1_CREDITS_BALANCE") ||
      /^\s*upstream 429\b[^:]*\b(?:QUOTA_EXHAUSTED|INSUFFICIENT_G1_CREDITS_BALANCE):/i.test(
        msgStr,
      ) ||
      /^\s*(?:Rate limit exceeded:\s*)?upstream 429\b/i.test(msgStr);
    if (!isCooldownOrRateLimit) {
      return null;
    }
    const { next, changed } = prependModelPrefix(errObj, model);
    if (!changed) return null;
    return {
      body: JSON.stringify({ ...parsed, error: next }),
      contentType: "application/json",
    };
  }

  if (status === 502) {
    const msgStr = typeof errObj.message === "string" ? errObj.message : "";
    if (!/^\s*(?:Internal server error:\s*)?Upstream stopped generation due to content policy:/i.test(msgStr)) {
      return null;
    }
    if (parsed.type === "error" && typeof errObj.type === "string") {
      if (errObj.code === "content_policy_violation") return null;
      const nextErr = { ...errObj, code: "content_policy_violation" };
      if (errObj.code && errObj.code !== "content_policy_violation" && !nextErr.upstream_code) {
        nextErr.upstream_code = errObj.code;
      }
      return {
        body: JSON.stringify({ ...parsed, error: nextErr }),
        contentType: "application/json",
      };
    }
    if (typeof errObj.code === "number") {
      if (errObj.type === "content_policy_violation") return null;
      return {
        body: JSON.stringify({
          ...parsed,
          error: { ...errObj, type: "content_policy_violation" },
        }),
        contentType: "application/json",
      };
    }
    if (errObj.code === "content_policy_violation") return null;
    const nextErr = { ...errObj, code: "content_policy_violation" };
    if (errObj.code && errObj.code !== "content_policy_violation" && !nextErr.upstream_code) {
      nextErr.upstream_code = errObj.code;
    }
    return {
      body: JSON.stringify({ ...parsed, error: nextErr }),
      contentType: "application/json",
    };
  }

  if (status === 503 || status === 529) {
    const msgStr = typeof errObj.message === "string" ? errObj.message : "";
    const isServiceWide =
      !msgStr.trim() ||
      /no account can serve|no ready accounts|no accounts|server shutting down|service stopped|request_canceled/i.test(
        msgStr,
      );
    if (isServiceWide) {
      return null;
    }

    const isCapacity =
      hasDetailReason(errObj, "MODEL_CAPACITY_EXHAUSTED") ||
      (status === 503 &&
        /^(?:Service unavailable:\s*)?upstream 503\b[^:]*\bMODEL_CAPACITY_EXHAUSTED:/i.test(
          msgStr,
        )) ||
      (status === 529 &&
        (/^Overloaded:/i.test(msgStr) ||
          (parsed.type === "error" && errObj.type === "overloaded_error") ||
          /upstream 529\b[^:]*\bMODEL_CAPACITY_EXHAUSTED:/i.test(msgStr)));

    if (!isCapacity) {
      return null;
    }

    const { next, changed } = prependModelPrefix(errObj, model);
    if (!changed) return null;
    return {
      body: JSON.stringify({ ...parsed, error: next }),
      contentType: "application/json",
    };
  }

  return null;
}

export function extractNativeUpstreamSession(headers, protocol, parsedBody) {
  if (protocol === "anthropic") {
    const rawUserId = parsedBody?.metadata?.user_id;
    if (typeof rawUserId === "string" && rawUserId.trim()) {
      const trimmed = rawUserId.trim();
      let jsonSessionHandled = false;
      if (trimmed.startsWith("{")) {
        const parsed = tryParseJsonObject(trimmed);
        if (parsed && typeof parsed.session_id === "string") {
          jsonSessionHandled = true;
          const sid = parsed.session_id.trim();
          if (sid) return sid;
        }
      }
      if (!jsonSessionHandled) {
        const match = trimmed.match(/_session_([0-9a-fA-F-]+)$/);
        if (match && match[1]) return match[1];
        return trimmed;
      }
    }
  } else if (protocol === "chat" || protocol === "responses") {
    for (const hName of ["session_id", "conversation_id"]) {
      const val = headers?.get?.(hName);
      if (val && val.trim()) return val.trim();
    }
  }

  for (const hName of [
    "x-claude-code-session-id",
    "x-session-id",
    "x-opencode-session",
    "x-opencode-session-id",
  ]) {
    const val = headers?.get?.(hName);
    if (val && val.trim()) return val.trim();
  }

  if (protocol === "chat" || protocol === "responses") {
    const cacheKey = parsedBody?.prompt_cache_key;
    if (typeof cacheKey === "string" && cacheKey.trim()) return cacheKey.trim();
    const user = parsedBody?.user;
    if (typeof user === "string" && user.trim()) return user.trim();
  }

  return "";
}

function extractRequestSessionToken(magpieSession, magpieSubagent, legacyCacheSession, nativeSession) {
  if (magpieSession) {
    return magpieSubagent
      ? `magpie-sub:${magpieSession}\0${magpieSubagent}`
      : `magpie:${magpieSession}`;
  }
  if (nativeSession) {
    return magpieSubagent
      ? `native-sub:${nativeSession}\0${magpieSubagent}`
      : `native:${nativeSession}`;
  }
  if (legacyCacheSession) {
    return magpieSubagent
      ? `cache-sub:${legacyCacheSession}\0${magpieSubagent}`
      : `cache:${legacyCacheSession}`;
  }
  return "";
}

function isJsonContentType(contentType) {
  if (typeof contentType !== "string") return false;
  return /^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/i.test(contentType.trim());
}

function rewriteAnthropicUserIdSession(rawUserId, auxSessionId) {
  if (typeof rawUserId !== "string" || !rawUserId.trim()) return auxSessionId;
  const trimmed = rawUserId.trim();
  if (trimmed.startsWith("{")) {
    const parsed = tryParseJsonObject(trimmed);
    if (parsed && typeof parsed.session_id === "string") {
      return JSON.stringify({ ...parsed, session_id: auxSessionId });
    }
  }
  if (/_session_[0-9a-fA-F-]+$/.test(trimmed)) {
    return trimmed.replace(/_session_[0-9a-fA-F-]+$/, `_session_${auxSessionId}`);
  }
  return auxSessionId;
}

export function createAgy2ApiFetch(config = {}) {
  const fetchImpl = config.fetchImpl ?? globalThis.fetch;
  const ttlMs =
    typeof config.cacheAffinityTtlMs === "number" &&
    Number.isFinite(config.cacheAffinityTtlMs) &&
    config.cacheAffinityTtlMs >= 0
      ? config.cacheAffinityTtlMs
      : DEFAULT_CACHE_AFFINITY_TTL_MS;
  const minBodyBytes =
    typeof config.cacheAffinityMinBodyBytes === "number" &&
    Number.isFinite(config.cacheAffinityMinBodyBytes) &&
    config.cacheAffinityMinBodyBytes >= 0
      ? config.cacheAffinityMinBodyBytes
      : DEFAULT_CACHE_AFFINITY_MIN_BODY_BYTES;
  const maxAuxOutputTokens =
    typeof config.cacheAffinityMaxAuxOutputTokens === "number" &&
    Number.isFinite(config.cacheAffinityMaxAuxOutputTokens) &&
    config.cacheAffinityMaxAuxOutputTokens >= 0
      ? config.cacheAffinityMaxAuxOutputTokens
      : DEFAULT_CACHE_AFFINITY_MAX_AUX_OUTPUT_TOKENS;
  const nowFn = typeof config.nowFn === "function" ? config.nowFn : Date.now;

  return async function agy2apiFetch(input, init = {}) {
    const authSnapshot =
      typeof config.getAuth === "function"
        ? resolveAuth(await config.getAuth(), {
            defaultBaseUrl: config.defaultBaseUrl ?? config.baseUrl,
          })
        : null;
    const baseUrl = authSnapshot
      ? authSnapshot.baseUrl
      : normalizeBaseUrl(config.baseUrl);
    const apiKey = authSnapshot ? authSnapshot.apiKey : (config.apiKey || "");
    const adminUsername = authSnapshot
      ? authSnapshot.adminUsername
      : (config.adminUsername || "admin");
    const adminPassword = authSnapshot
      ? authSnapshot.adminPassword
      : (config.adminPassword || "");

    const rawUrl =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    if (init?.headers) {
      new Headers(init.headers).forEach((v, k) => headers.set(k, v));
    }

    const { protocol, url: targetUrl } = rewriteUpstreamUrl(
      rawUrl,
      baseUrl,
      headers,
      config.baseUrl,
    );
    const method = init?.method ?? (input instanceof Request ? input.method : "POST");
    const targetRelPath = stripRootPrefix(new URL(targetUrl).pathname, baseUrl);
    const { rest: versionlessPath } = splitVersionPrefix(targetRelPath);
    const isGenEndpoint = isGenerationEndpoint(protocol, versionlessPath, method);
    const isModelEndpoint = isSessionPartitionEndpoint(protocol, versionlessPath, method);

    const magpieSession = (headers.get("x-magpie-session") || "").trim();
    const magpieSubagent = (headers.get("x-magpie-subagent") || "").trim();
    const legacyCacheSession = (headers.get("x-agy2api-cache-session") || "").trim();
    const effort = headers.get("x-magpie-effort");

    for (const key of [...headers.keys()]) {
      if (key.toLowerCase().startsWith("x-magpie-")) {
        headers.delete(key);
      }
    }
    headers.delete("x-agy2api-cache-session");

    const authScope = { baseUrl, apiKey, adminUsername, adminPassword };

    if (apiKey) {
      if (protocol === "gemini") {
        headers.set("x-goog-api-key", apiKey);
        headers.set("authorization", `Bearer ${apiKey}`);
        headers.delete("x-api-key");
      } else if (protocol === "anthropic") {
        headers.set("x-api-key", apiKey);
        headers.set("authorization", `Bearer ${apiKey}`);
        headers.delete("x-goog-api-key");
      } else if (protocol === "chat" || protocol === "responses") {
        headers.set("authorization", `Bearer ${apiKey}`);
        headers.delete("x-goog-api-key");
        headers.delete("x-api-key");
      } else {
        headers.set("authorization", `Bearer ${apiKey}`);
      }
    }

    let body = init?.body;
    if (body === undefined && input instanceof Request && input.body !== null) {
      body = await input.text();
    }

    const effectiveSignal = init?.signal ?? (input instanceof Request ? input.signal : undefined);

    let requestedModel =
      protocol === "gemini" ? extractGeminiModelFromPath(new URL(targetUrl).pathname) : "";
    const bodyText = decodeBodyText(body);

    let activePrefixKey = null;
    let isAuxDowngrade = false;
    let warmHit = null;
    let pendingWarmEntry = null;
    let parsedBody = null;
    let auxTicket = null;
    let preSanitizeSnapshot = null;
    let preserveCacheEffortResolved = null;

    if (bodyText !== null) {
      try {
        const obj = JSON.parse(bodyText);
        if (obj && typeof obj === "object" && !Array.isArray(obj)) {
          parsedBody = obj;
        }
      } catch {
        parsedBody = null;
      }

      if (parsedBody && RELAY_FIELD in parsedBody) {
        delete parsedBody[RELAY_FIELD];
        body = JSON.stringify(parsedBody);
        headers.delete("content-length");
      }

      if (isGenEndpoint && parsedBody) {
        const preModel =
          requestedModel || (typeof parsedBody.model === "string" ? parsedBody.model.trim() : "");
        preSanitizeSnapshot = extractConversationSnapshot(protocol, parsedBody, effort);
        const preNativeSession = extractNativeUpstreamSession(headers, protocol, parsedBody);
        const postDigest = computePostRelayRequestDigest(protocol, preModel, preSanitizeSnapshot);
        auxTicket = consumeAuxIsolationTicket({
          candidateSessionIds: [
            preNativeSession,
            magpieSession,
            headers.get("x-session-id"),
            headers.get("x-claude-code-session-id"),
            headers.get("x-opencode-session"),
            headers.get("x-opencode-session-id"),
            headers.get("session_id"),
            headers.get("conversation_id"),
          ],
          bareTargetModel: stripModelPrefix(preModel),
          postRelayRequestDigest: postDigest,
          nowMs: nowFn(),
        });
        if (auxTicket) {
          headers.set("x-session-id", auxTicket.auxSessionId);
          headers.delete("x-claude-code-session-id");
          headers.delete("x-opencode-session");
          headers.delete("x-opencode-session-id");
          headers.delete("session_id");
          headers.delete("conversation_id");
          if (
            protocol === "anthropic" &&
            isPlainObject(parsedBody.metadata) &&
            typeof parsedBody.metadata.user_id === "string" &&
            parsedBody.metadata.user_id.trim()
          ) {
            parsedBody.metadata = {
              ...parsedBody.metadata,
              user_id: rewriteAnthropicUserIdSession(
                parsedBody.metadata.user_id,
                auxTicket.auxSessionId,
              ),
            };
            body = JSON.stringify(parsedBody);
            headers.delete("content-length");
          }
          markTicketUpstreamExecuted(auxTicket, { outcome: "isolated" });
        }
      }

      // Item A: Second-pass prompt sanitization in provider fetch (no 250ms budget)
      if (isGenEndpoint && parsedBody) {
        try {
          const pluginOpts =
            typeof config.getPluginOptions === "function" ? config.getPluginOptions() : undefined;
          const sanitized = sanitizeRequestBody(protocol, parsedBody, pluginOpts);
          if (sanitized !== undefined) {
            parsedBody = sanitized;
            body = JSON.stringify(parsedBody);
            headers.delete("content-length");
          }
        } catch {
          // fail-open: preserve original parsedBody and body
        }
      }

      if (!requestedModel && parsedBody && typeof parsedBody.model === "string") {
        requestedModel = parsedBody.model.trim();
      }
    }

    const nativeSession = extractNativeUpstreamSession(headers, protocol, parsedBody);
    const bodyBlocksSessionCheck =
      String(method || "POST").toUpperCase() === "POST" &&
      (protocol === "anthropic" || protocol === "chat" || protocol === "responses") &&
      bodyText !== null &&
      !parsedBody;
    const hasResponsesPrevId =
      protocol === "responses" &&
      typeof parsedBody?.previous_response_id === "string" &&
      parsedBody.previous_response_id.trim().length > 0;

    if (
      isModelEndpoint &&
      !nativeSession &&
      magpieSession &&
      !bodyBlocksSessionCheck &&
      !hasResponsesPrevId
    ) {
      if (magpieSubagent) {
        const subHash = sha256Hex(JSON.stringify([magpieSession, magpieSubagent])).slice(0, 32);
        headers.set("x-session-id", `magpie-sub-v1-${subHash}`);
      } else {
        headers.set("x-session-id", magpieSession);
      }
    }

    const sessionToken = extractRequestSessionToken(
      magpieSession,
      magpieSubagent,
      legacyCacheSession,
      nativeSession,
    );

    if (bodyText !== null && parsedBody) {
      // Magpie translates thinking.type="disabled" on Claude Sonnet 5.5 into Anthropic's
      // {"type":"between_tools"} (ThinkOff), whereas Antigravity2API only accepts
      // enabled|adaptive|disabled and implements ThinkOff (HideThinking + lowest tier) via
      // {"type":"disabled"}.
      if (
        isModelEndpoint &&
        protocol === "anthropic" &&
        isPlainObject(parsedBody.thinking) &&
        parsedBody.thinking.type === "between_tools"
      ) {
        parsedBody.thinking = { type: "disabled" };
        body = JSON.stringify(parsedBody);
        headers.delete("content-length");
      }

      // Item C: Dynamic xhigh passthrough for Gemini models supporting xhigh (no forced includeThoughts)
      if (
        isGenEndpoint &&
        protocol === "gemini" &&
        effort?.trim().toLowerCase() === "xhigh" &&
        requestedModel
      ) {
        const preCheck = resolveRequestEffortAndMaxOutput("gemini", parsedBody, effort);
        if (!preCheck.disabled) {
          if (!getDiscoveredModels(authScope)) {
            await ensureModelsDiscovered(authScope, undefined, {
              fetchImpl,
              signal: effectiveSignal,
              timeoutMs: 3000,
            });
          }
          if (isXhighGeminiModel(authScope, requestedModel)) {
            const genKey = isPlainObject(parsedBody.generationConfig)
              ? "generationConfig"
              : isPlainObject(parsedBody.generation_config)
                ? "generation_config"
                : "generationConfig";
            const genCfg = isPlainObject(parsedBody[genKey]) ? { ...parsedBody[genKey] } : {};
            const tcKey = isPlainObject(genCfg.thinkingConfig)
              ? "thinkingConfig"
              : isPlainObject(genCfg.thinking_config)
                ? "thinking_config"
                : genKey === "generation_config"
                  ? "thinking_config"
                  : "thinkingConfig";
            const nextThinking = isPlainObject(genCfg[tcKey]) ? { ...genCfg[tcKey] } : {};
            const levelKey =
              "thinkingLevel" in nextThinking
                ? "thinkingLevel"
                : "thinking_level" in nextThinking
                  ? "thinking_level"
                  : tcKey === "thinking_config"
                    ? "thinking_level"
                    : "thinkingLevel";
            const hadBudget =
              "thinkingBudget" in nextThinking || "thinking_budget" in nextThinking;
            if (nextThinking[levelKey] !== "xhigh" || hadBudget) {
              delete nextThinking.thinkingBudget;
              delete nextThinking.thinking_budget;
              nextThinking[levelKey] = "xhigh";
              genCfg[tcKey] = nextThinking;
              parsedBody[genKey] = genCfg;
              body = JSON.stringify(parsedBody);
              headers.delete("content-length");
            }
          }
        }
      }

      // Item B: Cache-affinity effort preservation across ALL 4 protocols
      if (isGenEndpoint && requestedModel && !auxTicket) {
        let preserveCacheEffort =
          typeof config.preserveCacheEffort === "boolean"
            ? config.preserveCacheEffort
            : true;
        if (typeof config.getPreserveCacheEffort === "function") {
          try {
            const dynamicPreserve = await config.getPreserveCacheEffort();
            if (typeof dynamicPreserve === "boolean") {
              preserveCacheEffort = dynamicPreserve;
            }
          } catch {
            // fail-open to static/default
          }
        }
        preserveCacheEffortResolved = preserveCacheEffort;

        const modelEffortMeta = resolveModelEffortMetadata(authScope, requestedModel);
        if (preserveCacheEffort === true && !modelEffortMeta.skip) {
          const effectiveAuth =
            apiKey ||
            headers.get("authorization") ||
            headers.get("x-api-key") ||
            headers.get("x-goog-api-key") ||
            "";
          const apiKeyDigest = effectiveAuth ? sha256Hex(effectiveAuth) : "";
          const prefixKey = computePrefixKey(
            baseUrl,
            apiKeyDigest,
            sessionToken,
            protocol,
            requestedModel,
            parsedBody,
          );
          if (prefixKey) {
            activePrefixKey = prefixKey;
            const {
              effort: reqEffort,
              rank: reqRank,
              maxOutputTokens: reqMaxOutput,
              disabled: reqDisabled,
              slot: reqSlot,
              budgetTokens: reqBudgetTokens,
            } = resolveRequestEffortAndMaxOutput(protocol, parsedBody, effort);

            if (!reqDisabled) {
              const now = nowFn();
              const warm = getFreshWarmEntry(prefixKey, now, ttlMs);
              const currentBodyStr = typeof body === "string" ? body : bodyText;
              const bodyBytes = Buffer.byteLength(currentBodyStr, "utf8");

              const samePhysicalVariant =
                warm !== null &&
                Array.isArray(modelEffortMeta.thinkingLevels) &&
                resolveEffectiveVariant(reqEffort, modelEffortMeta.thinkingLevels) ===
                  resolveEffectiveVariant(warm.effort, modelEffortMeta.thinkingLevels);

              const candidateAux =
                warm !== null &&
                !samePhysicalVariant &&
                bodyBytes >= minBodyBytes &&
                reqRank !== null &&
                warm.effortRank !== null &&
                reqRank < warm.effortRank &&
                reqMaxOutput !== null &&
                reqMaxOutput <= maxAuxOutputTokens &&
                (warm.maxOutputTokens == null || reqMaxOutput <= warm.maxOutputTokens * 0.5);

              if (candidateAux) {
                let modified = false;
                if (protocol === "gemini") {
                  const genKey = isPlainObject(parsedBody.generationConfig)
                    ? "generationConfig"
                    : isPlainObject(parsedBody.generation_config)
                      ? "generation_config"
                      : "generationConfig";
                  const genCfg = isPlainObject(parsedBody[genKey])
                    ? { ...parsedBody[genKey] }
                    : {};
                  const tcKey = isPlainObject(genCfg.thinkingConfig)
                    ? "thinkingConfig"
                    : isPlainObject(genCfg.thinking_config)
                      ? "thinking_config"
                      : genKey === "generation_config"
                        ? "thinking_config"
                        : "thinkingConfig";
                  const existingTc = isPlainObject(genCfg[tcKey]) ? genCfg[tcKey] : null;
                  if (reqSlot === "level" && existingTc) {
                    const nextTc = { ...existingTc };
                    const levelKey =
                      "thinkingLevel" in nextTc ? "thinkingLevel" : "thinking_level";
                    nextTc[levelKey] = warm.effort;
                    genCfg[tcKey] = nextTc;
                    parsedBody[genKey] = genCfg;
                    modified = true;
                  } else if (reqSlot === "budget" && existingTc) {
                    const restoredBudget =
                      warm.budgetTokens ?? EFFORT_TO_BUDGET[warm.effort] ?? null;
                    if (typeof restoredBudget === "number" && restoredBudget > 0) {
                      const nextTc = { ...existingTc };
                      const budgetKey =
                        "thinkingBudget" in nextTc ? "thinkingBudget" : "thinking_budget";
                      nextTc[budgetKey] = restoredBudget;
                      genCfg[tcKey] = nextTc;
                      parsedBody[genKey] = genCfg;
                      modified = true;
                    }
                  }
                } else if (protocol === "anthropic") {
                  if (reqSlot === "output_config" && isPlainObject(parsedBody.output_config)) {
                    parsedBody.output_config = {
                      ...parsedBody.output_config,
                      effort: warm.effort,
                    };
                    modified = true;
                  } else if (reqSlot === "budget" && isPlainObject(parsedBody.thinking)) {
                    const restoredBudget =
                      warm.budgetTokens ?? EFFORT_TO_BUDGET[warm.effort] ?? null;
                    if (
                      typeof restoredBudget === "number" &&
                      restoredBudget > 0 &&
                      typeof parsedBody.max_tokens === "number" &&
                      restoredBudget < parsedBody.max_tokens
                    ) {
                      parsedBody.thinking = {
                        ...parsedBody.thinking,
                        budget_tokens: restoredBudget,
                      };
                      modified = true;
                    }
                  }
                } else if (protocol === "chat") {
                  if (reqSlot === "reasoning" && isPlainObject(parsedBody.reasoning)) {
                    parsedBody.reasoning = {
                      ...parsedBody.reasoning,
                      effort: warm.effort,
                    };
                    modified = true;
                  } else if (reqSlot === "reasoning_effort") {
                    parsedBody.reasoning_effort = warm.effort;
                    modified = true;
                  }
                } else if (protocol === "responses") {
                  if (reqSlot === "reasoning" && isPlainObject(parsedBody.reasoning)) {
                    parsedBody.reasoning = {
                      ...parsedBody.reasoning,
                      effort: warm.effort,
                    };
                    modified = true;
                  }
                }
                if (modified) {
                  isAuxDowngrade = true;
                  warmHit = warm;
                  body = JSON.stringify(parsedBody);
                  headers.delete("content-length");
                }
              } else if (
                reqRank !== null &&
                (reqMaxOutput == null || reqMaxOutput > maxAuxOutputTokens)
              ) {
                pendingWarmEntry = {
                  seq: ++nextWarmSeq,
                  effort: reqEffort,
                  effortRank: reqRank,
                  maxOutputTokens: reqMaxOutput ?? null,
                  budgetTokens: reqBudgetTokens ?? null,
                };
              }
            }
          }
        }
      }
    }

    const gen = cacheGeneration;
    let inFlightState = null;
    if (pendingWarmEntry && activePrefixKey) {
      inFlightState = inFlightWarmKeys.get(activePrefixKey);
      if (!inFlightState) {
        inFlightState = { count: 0, maxCommittedSeq: 0 };
        inFlightWarmKeys.set(activePrefixKey, inFlightState);
      }
      inFlightState.count += 1;
    }

    let res;
    try {
      res = await fetchImpl(targetUrl, {
        ...init,
        ...(effectiveSignal ? { signal: effectiveSignal } : {}),
        method,
        headers,
        body,
      });

      if (res.ok && gen === cacheGeneration) {
        if (isAuxDowngrade && warmHit && activePrefixKey) {
          if (prefixEffortCache.get(activePrefixKey) === warmHit) {
            warmHit.updatedAt = nowFn();
          }
        } else if (pendingWarmEntry && activePrefixKey) {
          const existing = prefixEffortCache.get(activePrefixKey);
          const minAllowedSeq = Math.max(
            existing?.seq ?? 0,
            inFlightState?.maxCommittedSeq ?? 0,
          );
          if (pendingWarmEntry.seq >= minAllowedSeq) {
            const now = nowFn();
            saveWarmEntry(
              activePrefixKey,
              { ...pendingWarmEntry, updatedAt: now },
              now,
              ttlMs,
            );
            if (inFlightState) {
              inFlightState.maxCommittedSeq = pendingWarmEntry.seq;
            }
          }
        }

        if (
          !auxTicket &&
          !isAuxDowngrade &&
          !magpieSubagent &&
          isGenEndpoint &&
          preSanitizeSnapshot &&
          preserveCacheEffortResolved !== false &&
          (pendingWarmEntry !== null ||
            preSanitizeSnapshot.effortInfo.maxOutputTokens == null ||
            preSanitizeSnapshot.effortInfo.maxOutputTokens > maxAuxOutputTokens)
        ) {
          const bareReq = stripModelPrefix(requestedModel);
          const metaEntry = bareReq ? getModelMetadataMap(authScope).get(bareReq) : null;
          commitMainSessionFromFetch({
            candidateSessionIds: [nativeSession, magpieSession],
            bareModel: bareReq,
            snapshot: preSanitizeSnapshot,
            headerEffort: effort,
            defaultThinkingLevel: metaEntry?.defaultThinkingLevel ?? null,
            nowMs: nowFn(),
            ttlMs,
          });
        }
      }
    } finally {
      if (inFlightState && gen === cacheGeneration) {
        inFlightState.count -= 1;
        if (inFlightState.count <= 0 && inFlightWarmKeys.get(activePrefixKey) === inFlightState) {
          inFlightWarmKeys.delete(activePrefixKey);
        }
      }
    }

    if (
      res.status === 400 ||
      res.status === 401 ||
      res.status === 404 ||
      res.status === 429 ||
      res.status === 502 ||
      res.status === 503 ||
      res.status === 529
    ) {
      const contentType = res.headers.get("content-type") || "";
      if (!isJsonContentType(contentType)) {
        if (res.status === 401) {
          const outHeaders = new Headers(res.headers);
          outHeaders.set("x-magpie-sign-in", "kept");
          return new Response(res.body, {
            status: res.status,
            statusText: res.statusText,
            headers: outHeaders,
          });
        }
        return res;
      }
      const rawBuf = await res.arrayBuffer();
      const rawErrText = new TextDecoder("utf-8", { fatal: false }).decode(rawBuf);
      const normalized = normalizeUpstreamErrorResponse(
        rawErrText,
        res.status,
        requestedModel,
        { isModelEndpoint },
      );
      const outHeaders = new Headers(res.headers);
      outHeaders.delete("content-length");
      outHeaders.delete("content-encoding");
      if (normalized?.headers) {
        for (const [hk, hv] of Object.entries(normalized.headers)) {
          outHeaders.set(hk, hv);
        }
      } else if (res.status === 401) {
        outHeaders.set("x-magpie-sign-in", "kept");
      }
      if (normalized?.body !== undefined) {
        outHeaders.set("content-type", normalized.contentType);
        return new Response(normalized.body, {
          status: res.status,
          statusText: res.statusText,
          headers: outHeaders,
        });
      }
      return new Response(rawBuf, {
        status: res.status,
        statusText: res.statusText,
        headers: outHeaders,
      });
    }

    return res;
  };
}
