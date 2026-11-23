import crypto from "node:crypto";
import { normalizeBaseUrl, resolveAuth } from "./auth.mjs";
import {
  ensureModelsDiscovered,
  foldModelId,
  getDiscoveredModels,
  isXhighGeminiModel,
} from "./models.mjs";
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

const prefixEffortCache = new Map();
let nextWarmSeq = 0;

export function clearPrefixEffortCache() {
  prefixEffortCache.clear();
  nextWarmSeq = 0;
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
  if (foldModelId(requestedModel).variant !== null) return null;

  if (protocol === "gemini") {
    if (!Array.isArray(parsedBody.contents) || parsedBody.contents.length < 1) {
      return null;
    }
    const payload = stableStringify([
      baseUrl,
      apiKeyDigest,
      sessionToken,
      "gemini",
      requestedModel,
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
      requestedModel,
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
      requestedModel,
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
        requestedModel,
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
        requestedModel,
        [parsedBody.instructions ?? null, leadingSystem],
        firstUserOrMsg,
      ]);
      return crypto.createHash("sha256").update(payload).digest("hex");
    }
    return null;
  }

  return null;
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
    if (isPlainObject(parsedBody.thinking) && parsedBody.thinking.type === "disabled") {
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
    const roEffort = normalizeEffort(parsedBody.reasoning?.effort);
    const reEffort = normalizeEffort(parsedBody.reasoning_effort);
    if (roEffort === "none" || reEffort === "none") {
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

export function normalizeUpstreamErrorResponse(rawText, status, requestedModel) {
  const model = typeof requestedModel === "string" ? requestedModel.trim() : "";
  const parsed = tryParseJsonObject(rawText);
  if (!parsed || !isPlainObject(parsed.error)) {
    return null;
  }
  const errObj = parsed.error;

  if (status === 400) {
    const msgStr = typeof errObj.message === "string" ? errObj.message : "";
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

  if (status === 429) {
    const msgStr = typeof errObj.message === "string" ? errObj.message : "";
    if (/^\s*(?:no account can serve|no ready accounts|no available accounts)\b/i.test(msgStr)) {
      return null;
    }
    const isExplicitQuota =
      hasDetailReason(errObj, "QUOTA_EXHAUSTED", "INSUFFICIENT_G1_CREDITS_BALANCE") ||
      /^\s*upstream 429\b[^:]*\b(?:QUOTA_EXHAUSTED|INSUFFICIENT_G1_CREDITS_BALANCE):/i.test(
        msgStr,
      );
    if (!isExplicitQuota) {
      return null;
    }
    const { next, changed } = prependModelPrefix(errObj, model);
    if (!changed) return null;
    return {
      body: JSON.stringify({ ...parsed, error: next }),
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

function extractRequestSessionToken(headers, protocol, parsedBody) {
  const internalSession = headers.get("x-agy2api-cache-session");
  headers.delete("x-agy2api-cache-session");
  if (internalSession && internalSession.trim()) {
    return `magpie:${internalSession.trim()}`;
  }

  if (protocol === "anthropic") {
    const rawUserId = parsedBody?.metadata?.user_id;
    if (typeof rawUserId === "string" && rawUserId.trim()) {
      const trimmed = rawUserId.trim();
      if (trimmed.startsWith("{")) {
        try {
          const parsed = JSON.parse(trimmed);
          if (typeof parsed?.session_id === "string" && parsed.session_id.trim()) {
            return `anth:${parsed.session_id.trim()}`;
          }
        } catch {
          // ignore
        }
      }
      const idx = trimmed.indexOf("_session_");
      if (idx >= 0) {
        const sid = trimmed.slice(idx + "_session_".length).trim();
        if (sid) return `anth:${sid}`;
      }
    }
  } else if (protocol === "chat" || protocol === "responses") {
    for (const hName of ["session_id", "conversation_id"]) {
      const val = headers.get(hName);
      if (val && val.trim()) return `hdr:${hName}:${val.trim()}`;
    }
  }

  for (const hName of [
    "x-claude-code-session-id",
    "x-session-id",
    "x-opencode-session",
    "x-opencode-session-id",
  ]) {
    const val = headers.get(hName);
    if (val && val.trim()) return `hdr:${hName}:${val.trim()}`;
  }

  return "";
}

function isJsonContentType(contentType) {
  if (typeof contentType !== "string") return false;
  return /^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/i.test(contentType.trim());
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

    const effort = headers.get("x-magpie-effort");
    headers.delete("x-magpie-effort");

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

    if (bodyText !== null) {
      let parsedBody = null;
      try {
        const obj = JSON.parse(bodyText);
        if (obj && typeof obj === "object" && !Array.isArray(obj)) {
          parsedBody = obj;
        }
      } catch {
        parsedBody = null;
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

      const sessionToken = extractRequestSessionToken(headers, protocol, parsedBody);

      // Item C: Dynamic xhigh passthrough for Gemini models supporting xhigh (no forced includeThoughts)
      if (
        isGenEndpoint &&
        protocol === "gemini" &&
        effort?.trim().toLowerCase() === "xhigh" &&
        parsedBody &&
        requestedModel
      ) {
        const preCheck = resolveRequestEffortAndMaxOutput("gemini", parsedBody, effort);
        if (!preCheck.disabled) {
          if (!getDiscoveredModels(baseUrl)) {
            await ensureModelsDiscovered(
              { baseUrl, apiKey, adminUsername, adminPassword },
              undefined,
              {
                fetchImpl,
                signal: effectiveSignal,
                timeoutMs: 3000,
              },
            );
          }
          if (isXhighGeminiModel(baseUrl, requestedModel)) {
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
      if (isGenEndpoint && parsedBody && requestedModel) {
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

          const preserveCacheEffort =
            typeof config.preserveCacheEffort === "boolean"
              ? config.preserveCacheEffort
              : true;

          if (!reqDisabled && preserveCacheEffort === true) {
            const now = nowFn();
            const warm = getFreshWarmEntry(prefixKey, now, ttlMs);
            const currentBodyStr = typeof body === "string" ? body : bodyText;
            const bodyBytes = Buffer.byteLength(currentBodyStr, "utf8");

            const candidateAux =
              warm !== null &&
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
                if (reqSlot === "reasoning_effort") {
                  parsedBody.reasoning_effort = warm.effort;
                  modified = true;
                } else if (reqSlot === "reasoning" && isPlainObject(parsedBody.reasoning)) {
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
    } else {
      headers.delete("x-agy2api-cache-session");
    }

    const res = await fetchImpl(targetUrl, {
      ...init,
      ...(effectiveSignal ? { signal: effectiveSignal } : {}),
      method,
      headers,
      body,
    });

    if (res.ok) {
      if (isAuxDowngrade && warmHit) {
        warmHit.updatedAt = nowFn();
      } else if (pendingWarmEntry && activePrefixKey) {
        const now = nowFn();
        saveWarmEntry(activePrefixKey, { ...pendingWarmEntry, updatedAt: now }, now, ttlMs);
      }
    }

    if (res.status === 400 || res.status === 429 || res.status === 503 || res.status === 529) {
      const contentType = res.headers.get("content-type") || "";
      if (!isJsonContentType(contentType)) {
        return res;
      }
      const rawBuf = await res.arrayBuffer();
      const rawErrText = new TextDecoder("utf-8", { fatal: false }).decode(rawBuf);
      const normalized = normalizeUpstreamErrorResponse(rawErrText, res.status, requestedModel);
      const outHeaders = new Headers(res.headers);
      outHeaders.delete("content-length");
      outHeaders.delete("content-encoding");
      if (normalized) {
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
