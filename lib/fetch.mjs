import crypto from "node:crypto";
import { normalizeBaseUrl, resolveAuth } from "./auth.mjs";
import {
  ensureModelsDiscovered,
  foldModelId,
  getDiscoveredModels,
  isXhighGeminiModel,
} from "./models.mjs";

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

const prefixEffortCache = new Map();

export function clearPrefixEffortCache() {
  prefixEffortCache.clear();
}

function normalizeEffort(raw) {
  if (typeof raw !== "string") return null;
  const norm = raw.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(EFFORT_RANK, norm) ? norm : null;
}

function budgetTokensToEffort(budgetTokens) {
  if (typeof budgetTokens !== "number" || !Number.isFinite(budgetTokens)) return null;
  if (budgetTokens <= 0) return "minimal";
  if (budgetTokens <= 4096) return "low";
  if (budgetTokens <= 10240) return "medium";
  if (budgetTokens <= 32768) return "high";
  return "max";
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

function computePrefixKey(baseUrl, protocol, requestedModel, parsedBody) {
  if (!parsedBody || !requestedModel) return null;
  if (foldModelId(requestedModel).variant !== null) return null;

  if (protocol === "gemini") {
    if (!Array.isArray(parsedBody.contents) || parsedBody.contents.length < 1) {
      return null;
    }
    const payload = stableStringify([
      baseUrl,
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
    const thinkingLevel = normalizeEffort(
      parsedBody.generationConfig?.thinkingConfig?.thinkingLevel,
    );
    const effort = thinkingLevel ?? hdrEffort;
    const maxOutputTokens = firstPositiveInt(parsedBody.generationConfig?.maxOutputTokens);
    return {
      effort,
      rank: effort !== null ? EFFORT_RANK[effort] : null,
      maxOutputTokens,
    };
  }

  if (protocol === "anthropic") {
    const outputEffort = normalizeEffort(parsedBody.output_config?.effort);
    let thinkingEffort = null;
    if (parsedBody.thinking && typeof parsedBody.thinking === "object") {
      if (parsedBody.thinking.type === "disabled") {
        thinkingEffort = "minimal";
      } else if (parsedBody.thinking.type === "enabled") {
        thinkingEffort = budgetTokensToEffort(parsedBody.thinking.budget_tokens);
      }
    }
    const effort = outputEffort ?? thinkingEffort ?? hdrEffort;
    const maxOutputTokens = firstPositiveInt(parsedBody.max_tokens);
    return {
      effort,
      rank: effort !== null ? EFFORT_RANK[effort] : null,
      maxOutputTokens,
    };
  }

  if (protocol === "chat") {
    const effort =
      normalizeEffort(parsedBody.reasoning_effort ?? parsedBody.reasoning?.effort) ?? hdrEffort;
    const maxOutputTokens = firstPositiveInt(
      parsedBody.max_completion_tokens,
      parsedBody.max_tokens,
    );
    return {
      effort,
      rank: effort !== null ? EFFORT_RANK[effort] : null,
      maxOutputTokens,
    };
  }

  if (protocol === "responses") {
    const effort =
      normalizeEffort(parsedBody.reasoning?.effort ?? parsedBody.reasoning_effort) ?? hdrEffort;
    const maxOutputTokens = firstPositiveInt(
      parsedBody.max_output_tokens,
      parsedBody.max_tokens,
    );
    return {
      effort,
      rank: effort !== null ? EFFORT_RANK[effort] : null,
      maxOutputTokens,
    };
  }

  return { effort: null, rank: null, maxOutputTokens: null };
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
  if (prefixEffortCache.has(prefixKey)) {
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

export function detectProtocol(pathname) {
  if (/\/models(?:\/|$)|:(?:streamGenerateContent|generateContent|countTokens|embedContent)\b/i.test(pathname)) {
    return "gemini";
  }
  if (/\/messages(?:\/|$)/i.test(pathname)) {
    return "anthropic";
  }
  if (/\/responses(?:\/|$)/i.test(pathname)) {
    return "responses";
  }
  if (/\/chat\/completions(?:\/|$)/i.test(pathname)) {
    return "chat";
  }
  return "other";
}

export function extractGeminiModelFromPath(pathname) {
  const m = pathname.match(/\/models\/([^/:?#]+)/i);
  if (!m) return "";
  return m[1].split("@")[0].trim();
}

export function rewriteUpstreamUrl(rawUrl, baseUrl) {
  const root = normalizeBaseUrl(baseUrl);
  const parsed = new URL(rawUrl, root);
  const pathname = parsed.pathname;
  const protocol = detectProtocol(pathname);

  if (protocol === "gemini") {
    const modelsIdx = pathname.toLowerCase().lastIndexOf("/models");
    if (modelsIdx >= 0) {
      return {
        protocol,
        url: `${root}/v1beta${pathname.slice(modelsIdx)}${parsed.search}`,
      };
    }
    const cleanPath = pathname.replace(/^(?:\/v1beta)+/i, "");
    return {
      protocol,
      url: `${root}/v1beta${cleanPath.startsWith("/") ? cleanPath : `/${cleanPath}`}${parsed.search}`,
    };
  }

  if (protocol === "anthropic") {
    const msgIdx = pathname.toLowerCase().lastIndexOf("/messages");
    return {
      protocol,
      url: `${root}/v1${pathname.slice(msgIdx)}${parsed.search}`,
    };
  }

  if (protocol === "chat") {
    const chatIdx = pathname.toLowerCase().lastIndexOf("/chat/completions");
    return {
      protocol,
      url: `${root}/v1${pathname.slice(chatIdx)}${parsed.search}`,
    };
  }

  if (protocol === "responses") {
    const respIdx = pathname.toLowerCase().lastIndexOf("/responses");
    return {
      protocol,
      url: `${root}/v1${pathname.slice(respIdx)}${parsed.search}`,
    };
  }

  return {
    protocol,
    url: `${root}${pathname}${parsed.search}`,
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

export function normalizeUpstreamErrorResponse(rawText, status, requestedModel) {
  const model = typeof requestedModel === "string" ? requestedModel.trim() : "";

  if (status === 400) {
    const parsed = tryParseJsonObject(rawText);
    const msgStr = String(parsed?.error?.message ?? parsed?.message ?? rawText ?? "");
    const codeStr = typeof parsed?.error?.code === "string" ? parsed.error.code : "";
    const isPromptFeedbackBlock =
      Boolean(parsed?.promptFeedback?.blockReason) ||
      /\b(PROHIBITED_CONTENT|BLOCKLIST)\b/.test(rawText) ||
      (/\bSAFETY\b/.test(rawText) &&
        /(blockReason|promptFeedback|blocked|safety\s*filter)/i.test(rawText));
    const isContentRejection =
      /Upstream rejected the request content/i.test(msgStr) ||
      codeStr === "invalid_prompt" ||
      isPromptFeedbackBlock;

    if (!isContentRejection) {
      return null;
    }

    if (parsed?.type === "error" && parsed?.error && typeof parsed.error === "object") {
      // Anthropic shape: set error.code = "content_policy_violation", preserve error.type & error.message
      const nextErr = { ...parsed.error, code: "content_policy_violation" };
      return {
        body: JSON.stringify({ ...parsed, error: nextErr }),
        contentType: "application/json",
      };
    }

    if (
      parsed?.error &&
      typeof parsed.error === "object" &&
      typeof parsed.error.code === "number"
    ) {
      // Gemini shape: set error.type = "content_policy_violation", preserve numeric error.code, status, message
      const nextErr = { ...parsed.error, type: "content_policy_violation" };
      return {
        body: JSON.stringify({ ...parsed, error: nextErr }),
        contentType: "application/json",
      };
    }

    if (
      parsed?.error &&
      typeof parsed.error === "object" &&
      parsed.error.code === "invalid_prompt"
    ) {
      // OpenAI shape: keep error.code = "invalid_prompt", append flagged wording
      const origMsg = String(parsed.error.message || "").trim();
      const cleanedMsg = origMsg
        .replace(/\s*\(not a quota or rate limit\)/gi, "")
        .trim();
      const nextMsg = /flagged/i.test(cleanedMsg)
        ? cleanedMsg
        : `${cleanedMsg || "Upstream rejected the request content"} (flagged by upstream content policy)`;
      const nextErr = {
        ...parsed.error,
        code: "invalid_prompt",
        message: nextMsg,
      };
      return {
        body: JSON.stringify({ ...parsed, error: nextErr }),
        contentType: "application/json",
      };
    }

    if (parsed?.error && typeof parsed.error === "object") {
      const nextErr = {
        ...parsed.error,
        code: "content_policy_violation",
        type: parsed.error.type || "content_policy_violation",
      };
      return {
        body: JSON.stringify({ ...parsed, error: nextErr }),
        contentType: "application/json",
      };
    }

    return {
      body: JSON.stringify({
        ...(parsed || {}),
        error: {
          code: "content_policy_violation",
          type: "content_policy_violation",
          message: msgStr.trim() || "Upstream rejected the request content",
        },
      }),
      contentType: "application/json",
    };
  }

  if (status === 503 || status === 529) {
    // STRICT semantic check: service-wide unavailability on 503 passes through untouched
    if (status === 503) {
      const isServiceWide =
        !rawText.trim() ||
        /no ready accounts|no accounts|server shutting down|service stopped|request_canceled/i.test(
          rawText,
        );
      if (isServiceWide) {
        return null;
      }
    }

    const isModelOverload =
      status === 529 ||
      (status === 503 &&
        /(overloaded|capacity|MODEL_CAPACITY_EXHAUSTED|high demand|too busy)/i.test(rawText));

    if (!isModelOverload) {
      return null;
    }

    const parsed = tryParseJsonObject(rawText);
    const buildOverloadMsg = (origMsg) => {
      const base = String(origMsg || "").trim();
      const parts = [];
      if (model && !hasWholeModelToken(base, model)) {
        parts.push(`model ${model}:`);
      }
      parts.push(base || "upstream model overloaded");
      const joined = parts.join(" ");
      if (!/overloaded/i.test(joined)) {
        return `${joined} (overloaded)`;
      }
      return joined;
    };

    if (parsed) {
      if (parsed.error && typeof parsed.error === "object") {
        const errObj = { ...parsed.error };
        errObj.message = buildOverloadMsg(errObj.message ?? parsed.message ?? "");
        if (model && !errObj.model) errObj.model = model;
        if (!errObj.type) errObj.type = "overloaded_error";
        return {
          body: JSON.stringify({ ...parsed, error: errObj }),
          contentType: "application/json",
        };
      }
      const updated = { ...parsed };
      updated.message = buildOverloadMsg(updated.message ?? updated.error ?? "");
      if (model && !updated.model) updated.model = model;
      if (!updated.type) updated.type = "overloaded_error";
      return {
        body: JSON.stringify(updated),
        contentType: "application/json",
      };
    }

    return {
      body: JSON.stringify({
        error: {
          message: buildOverloadMsg(rawText),
          type: "overloaded_error",
          ...(model ? { model } : {}),
        },
      }),
      contentType: "application/json",
    };
  }

  if (status === 429) {
    const parsed = tryParseJsonObject(rawText);
    const indicatesQuota = /(quota|exhausted|cooldown|resource_exhausted)/i.test(rawText);

    const build429Msg = (origMsg) => {
      const base = String(origMsg || "").trim();
      const parts = [];
      if (model && !hasWholeModelToken(base, model)) {
        parts.push(`model ${model}:`);
      }
      parts.push(base || "rate limit exceeded");
      const joined = parts.join(" ");
      if (indicatesQuota) {
        const extra = [];
        if (!/RESOURCE_EXHAUSTED/i.test(joined)) extra.push("RESOURCE_EXHAUSTED");
        if (!/quota/i.test(joined)) extra.push("quota");
        if (extra.length > 0) return `${joined} (${extra.join(" ")})`;
      }
      return joined;
    };

    if (parsed) {
      if (parsed.error && typeof parsed.error === "object") {
        const errObj = { ...parsed.error };
        errObj.message = build429Msg(errObj.message ?? parsed.message ?? "");
        if (model && !errObj.model) errObj.model = model;
        if (indicatesQuota && !errObj.status) errObj.status = "RESOURCE_EXHAUSTED";
        return {
          body: JSON.stringify({ ...parsed, error: errObj }),
          contentType: "application/json",
        };
      }
      const updated = { ...parsed };
      updated.message = build429Msg(updated.message ?? updated.error ?? "");
      if (model && !updated.model) updated.model = model;
      if (indicatesQuota && !updated.status) updated.status = "RESOURCE_EXHAUSTED";
      return {
        body: JSON.stringify(updated),
        contentType: "application/json",
      };
    }

    return {
      body: JSON.stringify({
        error: {
          message: build429Msg(rawText),
          ...(model ? { model } : {}),
          ...(indicatesQuota ? { status: "RESOURCE_EXHAUSTED" } : {}),
        },
      }),
      contentType: "application/json",
    };
  }

  return null;
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
      typeof config.getAuth === "function" ? resolveAuth(await config.getAuth()) : null;
    const baseUrl = normalizeBaseUrl(authSnapshot?.baseUrl || config.baseUrl);
    const apiKey = authSnapshot?.apiKey || config.apiKey || "";
    const adminUsername = authSnapshot?.adminUsername || config.adminUsername || "admin";
    const adminPassword = authSnapshot?.adminPassword || config.adminPassword || "";

    const rawUrl =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const { protocol, url: targetUrl } = rewriteUpstreamUrl(rawUrl, baseUrl);

    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    if (init?.headers) {
      new Headers(init.headers).forEach((v, k) => headers.set(k, v));
    }

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

    let requestedModel =
      protocol === "gemini" ? extractGeminiModelFromPath(new URL(targetUrl).pathname) : "";
    const bodyText = decodeBodyText(body);

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

      if (!requestedModel && parsedBody && typeof parsedBody.model === "string") {
        requestedModel = parsedBody.model.split("@")[0].trim();
      }

      // Dynamic xhigh passthrough for Gemini models supporting xhigh
      if (
        protocol === "gemini" &&
        effort?.trim().toLowerCase() === "xhigh" &&
        parsedBody &&
        requestedModel
      ) {
        if (!getDiscoveredModels(baseUrl)) {
          await ensureModelsDiscovered(
            { baseUrl, apiKey, adminUsername, adminPassword },
            undefined,
            {
              fetchImpl,
              signal: init?.signal,
              timeoutMs: 3000,
            },
          );
        }
        if (isXhighGeminiModel(baseUrl, requestedModel)) {
          const genCfg =
            parsedBody.generationConfig && typeof parsedBody.generationConfig === "object"
              ? { ...parsedBody.generationConfig }
              : {};
          const prevThinking =
            genCfg.thinkingConfig && typeof genCfg.thinkingConfig === "object"
              ? { ...genCfg.thinkingConfig }
              : {};
          const nextThinking = {
            ...prevThinking,
            includeThoughts: true,
            thinkingLevel: "xhigh",
          };
          delete nextThinking.thinkingBudget;
          genCfg.thinkingConfig = nextThinking;
          parsedBody.generationConfig = genCfg;
          body = JSON.stringify(parsedBody);
          headers.delete("content-length");
        }
      }

      // Cache-affinity effort preservation across ALL 4 protocols
      if (parsedBody && requestedModel) {
        const prefixKey = computePrefixKey(baseUrl, protocol, requestedModel, parsedBody);
        if (prefixKey) {
          const {
            effort: reqEffort,
            rank: reqRank,
            maxOutputTokens: reqMaxOutput,
          } = resolveRequestEffortAndMaxOutput(protocol, parsedBody, effort);

          const liveOpts = typeof config.getOptions === "function" ? config.getOptions() : null;
          const preserveCacheEffort =
            typeof liveOpts?.preserveCacheEffort === "boolean"
              ? liveOpts.preserveCacheEffort
              : typeof config.preserveCacheEffort === "boolean"
                ? config.preserveCacheEffort
                : true;

          const now = nowFn();
          const warm = getFreshWarmEntry(prefixKey, now, ttlMs);
          const bodyBytes = Buffer.byteLength(bodyText, "utf8");

          const isAuxDowngrade =
            preserveCacheEffort === true &&
            warm !== null &&
            bodyBytes >= minBodyBytes &&
            reqRank !== null &&
            warm.effortRank !== null &&
            reqRank < warm.effortRank &&
            reqMaxOutput !== null &&
            reqMaxOutput <= maxAuxOutputTokens &&
            (warm.maxOutputTokens == null || reqMaxOutput <= warm.maxOutputTokens * 0.5);

          if (isAuxDowngrade) {
            warm.updatedAt = now;
            if (protocol === "gemini") {
              const genCfg =
                parsedBody.generationConfig && typeof parsedBody.generationConfig === "object"
                  ? { ...parsedBody.generationConfig }
                  : {};
              const restoredThinking = warm.thinkingConfig
                ? cloneJson(warm.thinkingConfig)
                : { thinkingLevel: warm.effort };
              if (warm.effort === "xhigh" && isXhighGeminiModel(baseUrl, requestedModel)) {
                restoredThinking.includeThoughts = true;
                restoredThinking.thinkingLevel = "xhigh";
                delete restoredThinking.thinkingBudget;
              }
              genCfg.thinkingConfig = restoredThinking;
              parsedBody.generationConfig = genCfg;
              body = JSON.stringify(parsedBody);
              headers.delete("content-length");
            } else if (protocol === "anthropic") {
              if (warm.anthropicThinking !== undefined) {
                parsedBody.thinking = cloneJson(warm.anthropicThinking);
              } else if (warm.anthropicOutputConfig !== undefined) {
                delete parsedBody.thinking;
              }
              if (warm.anthropicOutputConfig !== undefined) {
                parsedBody.output_config = cloneJson(warm.anthropicOutputConfig);
              } else if (warm.anthropicThinking !== undefined) {
                delete parsedBody.output_config;
              } else if (warm.effort) {
                parsedBody.output_config = {
                  ...(parsedBody.output_config && typeof parsedBody.output_config === "object"
                    ? parsedBody.output_config
                    : {}),
                  effort: warm.effort,
                };
              }
              if (
                parsedBody.thinking?.type === "enabled" &&
                typeof parsedBody.thinking.budget_tokens === "number" &&
                Number.isFinite(parsedBody.thinking.budget_tokens) &&
                parsedBody.thinking.budget_tokens >= parsedBody.max_tokens
              ) {
                parsedBody.max_tokens = Math.max(
                  warm.maxOutputTokens || 0,
                  parsedBody.thinking.budget_tokens + 1024,
                );
              }
              body = JSON.stringify(parsedBody);
              headers.delete("content-length");
            } else if (protocol === "chat") {
              if (warm.reasoningEffort !== undefined) {
                parsedBody.reasoning_effort = warm.reasoningEffort;
              } else if (warm.effort) {
                parsedBody.reasoning_effort = warm.effort;
              }
              if (warm.reasoning && typeof warm.reasoning === "object") {
                parsedBody.reasoning = {
                  ...(parsedBody.reasoning && typeof parsedBody.reasoning === "object"
                    ? parsedBody.reasoning
                    : {}),
                  ...cloneJson(warm.reasoning),
                };
              } else if (parsedBody.reasoning && typeof parsedBody.reasoning === "object") {
                parsedBody.reasoning = {
                  ...parsedBody.reasoning,
                  effort: warm.effort,
                };
              }
              body = JSON.stringify(parsedBody);
              headers.delete("content-length");
            } else if (protocol === "responses") {
              const prevReasoning =
                parsedBody.reasoning && typeof parsedBody.reasoning === "object"
                  ? parsedBody.reasoning
                  : {};
              const warmReasoning =
                warm.reasoning && typeof warm.reasoning === "object"
                  ? cloneJson(warm.reasoning)
                  : {};
              parsedBody.reasoning = {
                ...warmReasoning,
                ...prevReasoning,
                effort: warm.effort,
              };
              body = JSON.stringify(parsedBody);
              headers.delete("content-length");
            }
          } else if (reqRank !== null && (reqMaxOutput == null || reqMaxOutput > maxAuxOutputTokens)) {
            const entry = {
              effort: reqEffort,
              effortRank: reqRank,
              maxOutputTokens: reqMaxOutput ?? null,
              updatedAt: now,
            };
            if (protocol === "gemini") {
              const tc = parsedBody.generationConfig?.thinkingConfig;
              entry.thinkingConfig =
                tc && typeof tc === "object" ? cloneJson(tc) : { thinkingLevel: reqEffort };
            } else if (protocol === "anthropic") {
              if (parsedBody.thinking && typeof parsedBody.thinking === "object") {
                entry.anthropicThinking = cloneJson(parsedBody.thinking);
              }
              if (parsedBody.output_config && typeof parsedBody.output_config === "object") {
                entry.anthropicOutputConfig = cloneJson(parsedBody.output_config);
              }
            } else if (protocol === "chat") {
              if (typeof parsedBody.reasoning_effort === "string") {
                entry.reasoningEffort = parsedBody.reasoning_effort;
              }
              if (parsedBody.reasoning && typeof parsedBody.reasoning === "object") {
                entry.reasoning = cloneJson(parsedBody.reasoning);
              }
            } else if (protocol === "responses") {
              if (parsedBody.reasoning && typeof parsedBody.reasoning === "object") {
                entry.reasoning = cloneJson(parsedBody.reasoning);
              } else {
                entry.reasoning = { effort: reqEffort };
              }
            }
            saveWarmEntry(prefixKey, entry, now, ttlMs);
          }
        }
      }
    }

    const method = init?.method ?? (input instanceof Request ? input.method : "POST");
    const res = await fetchImpl(targetUrl, {
      ...init,
      method,
      headers,
      body,
    });

    if (res.status === 400 || res.status === 429 || res.status === 503 || res.status === 529) {
      const rawErrText = await res.text();
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
      return new Response(rawErrText, {
        status: res.status,
        statusText: res.statusText,
        headers: outHeaders,
      });
    }

    return res;
  };
}
