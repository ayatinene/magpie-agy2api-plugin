import {
  DEFAULT_BASE_URL,
  adminFetch,
  buildAuthScopeKey,
  clearAdminSettingsCache,
  fetchAdminSettingsCached,
  normalizeBaseUrl,
  resolveAuth,
} from "./auth.mjs";

export { DEFAULT_BASE_URL, normalizeBaseUrl, resolveAuth };

export const MODEL_CACHE_TTL_MS = 60_000;

const MODALITIES = ["text", "image", "audio", "video", "pdf"];
const EFFORT_ORDER = ["minimal", "low", "medium", "high", "xhigh", "max"];
const SYNTHETIC_EFFORT_LEVELS = new Set(["low", "medium", "high", "xhigh"]);
const MAX_BETA_PAGES = 100;
const EFFORT_SUFFIX_RE = /-(minimal|low|medium|high|xhigh|max)$/i;
const DISPLAY_SUFFIX_RE = /\s*\((?:minimal|low|medium|high|xhigh|max)\)\s*$/i;
const STANDARD_VIDEO_MIME_RE =
  /^video\/(mp4|webm|quicktime|x-matroska|mpeg|ogg|3gpp|x-msvideo|avi|mov|x-flv|wmv|mp2t|h264|hevc)(?:;.*)?$/i;
const STANDARD_AUDIO_MIME_RE = /^audio\/[a-z0-9.+-]+(?:;.*)?$/i;
const STANDARD_IMAGE_MIME_RE = /^image\/[a-z0-9.+-]+(?:;.*)?$/i;

const modelCache = new Map();
const inFlightDiscovery = new Map();
const latestScopeByRoot = new Map();

export function clearModelCache() {
  modelCache.clear();
  inFlightDiscovery.clear();
  latestScopeByRoot.clear();
  clearAdminSettingsCache();
}

export function foldModelId(rawId) {
  const clean = String(rawId || "").trim().replace(/^models\//, "");
  const match = clean.match(EFFORT_SUFFIX_RE);
  if (match) {
    return {
      baseId: clean.slice(0, match.index),
      variant: match[1].toLowerCase(),
    };
  }
  return { baseId: clean, variant: null };
}

export function titleCaseModelId(id) {
  const upperTokens = new Set(["gpt", "oss", "ai", "api"]);
  return String(id || "")
    .split("-")
    .filter(Boolean)
    .map((tok) => {
      const lower = tok.toLowerCase();
      if (upperTokens.has(lower)) return lower.toUpperCase();
      if (/^\d+[bmkt]$/i.test(tok)) return tok.toUpperCase();
      return tok.charAt(0).toUpperCase() + tok.slice(1);
    })
    .join(" ");
}

export function formatEffortLabel(level) {
  const norm = String(level || "").trim().toLowerCase();
  if (norm === "xhigh") return "XHigh";
  if (!norm) return "";
  return norm.charAt(0).toUpperCase() + norm.slice(1);
}

function toCapabilityModalities(list) {
  const set = new Set(Array.isArray(list) ? list : ["text"]);
  const out = {};
  for (const k of MODALITIES) out[k] = set.has(k);
  return out;
}

function firstPositive(...candidates) {
  for (const v of candidates) {
    const n = Number(v);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return null;
}

function extractSupportedMimeKeys(raw) {
  if (Array.isArray(raw)) {
    return raw.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim().toLowerCase());
  }
  if (raw && typeof raw === "object") {
    return Object.entries(raw)
      .filter(([, enabled]) => enabled !== false)
      .map(([k]) => String(k).trim().toLowerCase())
      .filter(Boolean);
  }
  return [];
}

function normalizeThinkingLevels(item) {
  const raw =
    item?.thinking_levels ??
    item?.supported_reasoning_levels ??
    item?.thinkingLevels ??
    [];
  if (!Array.isArray(raw)) return [];
  const out = [];
  const seen = new Set();
  for (const entry of raw) {
    let val = "";
    if (typeof entry === "string") {
      val = entry;
    } else if (entry && typeof entry === "object") {
      val = entry.effort ?? entry.level ?? entry.id ?? entry.name ?? "";
    }
    const norm = String(val || "").trim().toLowerCase();
    if (norm && !seen.has(norm)) {
      seen.add(norm);
      out.push(norm);
    }
  }
  return out;
}

function sortEfforts(levels) {
  const list = [...new Set(levels.map((l) => String(l || "").trim().toLowerCase()).filter(Boolean))];
  return list.sort((a, b) => {
    const ia = EFFORT_ORDER.indexOf(a);
    const ib = EFFORT_ORDER.indexOf(b);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.localeCompare(b);
  });
}

function deriveInputModalities(item) {
  const set = new Set(["text"]);
  if (item?.supports_images === true) {
    set.add("image");
  }
  const caps = item?.capabilities;
  if (caps && typeof caps === "object") {
    if (caps.images === true || caps.image === true || caps.vision === true) set.add("image");
    if (caps.audio === true || caps.transcription === true) set.add("audio");
    if (caps.video === true) set.add("video");
    if (caps.pdf === true || caps.documents === true) set.add("pdf");
  }
  if (Array.isArray(item?.input_modalities)) {
    for (const mod of item.input_modalities) {
      const m = String(mod || "").trim().toLowerCase();
      if (MODALITIES.includes(m)) set.add(m);
    }
  }
  const mimes = extractSupportedMimeKeys(item?.supported_mime_types);
  for (const mime of mimes) {
    if (STANDARD_IMAGE_MIME_RE.test(mime)) {
      set.add("image");
    } else if (STANDARD_AUDIO_MIME_RE.test(mime)) {
      set.add("audio");
    } else if (STANDARD_VIDEO_MIME_RE.test(mime)) {
      set.add("video");
    } else if (mime === "application/pdf" || mime.startsWith("application/pdf;")) {
      set.add("pdf");
    }
  }
  return MODALITIES.filter((m) => set.has(m));
}

export function resolveProtocolSpec(baseId, providerHint = "") {
  const prov = String(providerHint || "").trim().toUpperCase();
  const lower = String(baseId || "").toLowerCase();

  if (prov === "MODEL_PROVIDER_ANTHROPIC") {
    return { npm: "@ai-sdk/anthropic", apiPath: "/v1", family: "Claude" };
  }
  if (prov === "MODEL_PROVIDER_GOOGLE") {
    return { npm: "@ai-sdk/google", apiPath: "/v1beta", family: "Gemini" };
  }
  if (prov === "MODEL_PROVIDER_OPENAI") {
    return { npm: "@ai-sdk/openai-compatible", apiPath: "/v1", family: "GPT" };
  }

  if (lower.startsWith("claude")) {
    return { npm: "@ai-sdk/anthropic", apiPath: "/v1", family: "Claude" };
  }
  if (lower.startsWith("gemini") || lower.startsWith("imagen")) {
    return { npm: "@ai-sdk/google", apiPath: "/v1beta", family: "Gemini" };
  }
  if (lower.startsWith("gpt")) {
    return { npm: "@ai-sdk/openai-compatible", apiPath: "/v1", family: "GPT" };
  }
  const family = titleCaseModelId(lower.split("-")[0] || "OpenAI");
  return { npm: "@ai-sdk/openai-compatible", apiPath: "/v1", family };
}

function extractModelEntries(payload, sourceKind = "any") {
  let list = null;
  if (sourceKind === "admin") {
    if (payload && typeof payload === "object" && !Array.isArray(payload) && Array.isArray(payload.models)) {
      list = payload.models;
    }
  } else if (sourceKind === "v1") {
    if (payload && typeof payload === "object" && !Array.isArray(payload) && Array.isArray(payload.data)) {
      list = payload.data;
    }
  } else if (sourceKind === "beta") {
    if (payload && typeof payload === "object" && !Array.isArray(payload) && Array.isArray(payload.models)) {
      list = payload.models;
    }
  } else {
    list = Array.isArray(payload?.models)
      ? payload.models
      : Array.isArray(payload?.data)
        ? payload.data
        : Array.isArray(payload)
          ? payload
          : null;
  }
  if (!list) return null;

  const map = new Map();
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const raw =
      sourceKind === "beta"
        ? (item.baseModelId ?? item.id ?? item.name ?? item.model ?? "")
        : (item.id ?? item.baseModelId ?? item.name ?? item.model ?? "");
    if (typeof raw !== "string" || !raw.trim()) continue;
    const clean = raw.trim().replace(/^models\//, "");
    if (!clean) continue;
    map.set(clean, item);
  }
  if (list.length > 0 && map.size === 0) {
    return null;
  }
  return map;
}

function rawDisplayName(item) {
  const dn = item?.display_name ?? item?.displayName;
  if (typeof dn === "string" && dn.trim()) return dn;
  const n = item?.name;
  if (typeof n === "string" && n.trim() && !/^models\//i.test(n.trim())) return n;
  return "";
}

function cleanDisplayName(rawName, baseId, stripVariantSuffix = false) {
  if (typeof rawName !== "string") return "";
  let s = rawName.trim();
  if (!s) return "";
  if (stripVariantSuffix) {
    s = s.replace(DISPLAY_SUFFIX_RE, "").trim();
  }
  if (!s || s.toLowerCase() === String(baseId).toLowerCase()) return "";
  return s;
}

function buildSingleModelEntry({
  id,
  displayName,
  primary,
  fallbackItem = {},
  variants = {},
  supportsThinkingExtra = false,
  root,
  providerHint = "",
}) {
  const context =
    firstPositive(
      primary.input_token_limit,
      primary.context_length,
      primary.max_input_tokens,
      primary.inputTokenLimit,
      primary.max_context_length,
      primary.max_model_len,
      primary.maxTokens,
      primary.max_tokens,
      fallbackItem.input_token_limit,
      fallbackItem.context_length,
      fallbackItem.max_input_tokens,
      fallbackItem.inputTokenLimit,
    ) ?? 0;

  const output =
    firstPositive(
      primary.output_token_limit,
      primary.max_output_tokens,
      primary.max_completion_tokens,
      primary.outputTokenLimit,
      fallbackItem.output_token_limit,
      fallbackItem.max_output_tokens,
      fallbackItem.max_completion_tokens,
      fallbackItem.outputTokenLimit,
    ) ?? 0;

  const hasPrimaryModalityFields =
    primary.capabilities !== undefined ||
    primary.input_modalities !== undefined ||
    primary.supported_mime_types !== undefined ||
    primary.supports_images !== undefined;
  const modalitySource = hasPrimaryModalityFields ? primary : fallbackItem;
  const inputModalities = deriveInputModalities(modalitySource);

  const isImageOutput =
    primary.capabilities?.image_generation === true ||
    fallbackItem.capabilities?.image_generation === true ||
    (Array.isArray(primary.output_modalities) && primary.output_modalities.includes("image")) ||
    /image|imagen/i.test(id);
  const outputModalities = isImageOutput ? ["image"] : ["text"];

  const supportsThinking =
    primary.capabilities?.thinking === true ||
    primary.supports_thinking === true ||
    primary.thinking === true ||
    fallbackItem.capabilities?.thinking === true ||
    supportsThinkingExtra;
  const reasoning = isImageOutput ? false : supportsThinking || Object.keys(variants).length > 0;

  const { npm, apiPath, family } = resolveProtocolSpec(
    id,
    providerHint || primary.provider || fallbackItem.provider,
  );

  return {
    id,
    providerID: "agy2api",
    name: displayName,
    family,
    api: {
      id,
      url: `${root}${apiPath}`,
      npm,
    },
    status: "active",
    headers: {},
    options: {},
    cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
    limit: { context, output },
    capabilities: {
      temperature: true,
      reasoning,
      attachment: inputModalities.length > 1,
      toolcall: !isImageOutput,
      input: toCapabilityModalities(inputModalities),
      output: toCapabilityModalities(outputModalities),
      interleaved: false,
    },
    release_date: "",
    variants,
  };
}

function normalizeModelMapping(raw) {
  if (!raw) return null;
  if (raw instanceof Map) return raw;
  if (typeof raw === "object" && !Array.isArray(raw)) {
    const m = new Map();
    for (const [k, v] of Object.entries(raw)) {
      if (typeof k === "string" && k.trim() && typeof v === "string" && v.trim()) {
        m.set(k.trim(), v.trim());
      }
    }
    return m;
  }
  return null;
}

export function buildModelsFromRawEntries(rawEntries, baseUrl = DEFAULT_BASE_URL, opts = {}) {
  const { foldEffortVariants = false } = opts;
  const modelMapping = normalizeModelMapping(opts.modelMapping);
  const root = normalizeBaseUrl(baseUrl);
  const realEntries = new Map();

  for (const [rawId, item] of rawEntries.entries()) {
    const cleanRawId = String(rawId || "").trim().replace(/^models\//, "");
    if (!cleanRawId || !item || typeof item !== "object") continue;
    realEntries.set(cleanRawId, item);
  }

  const models = {};
  const xhighGeminiModels = new Set();
  const modelQuotaGroupMap = new Map();
  const modelMetadataMap = new Map();

  for (const [id, item] of realEntries.entries()) {
    if (item.capabilities?.transcription === true || item.capabilities?.completion === true) {
      continue;
    }

    const providerHint = String(item.provider ?? "").trim();
    const quotaGroup = String(item.quota_group ?? "").trim();
    const defaultThinkingLevel =
      String(
        item.default_thinking_level ??
          item.default_reasoning_level ??
          item.defaultThinkingLevel ??
          "",
      )
        .trim()
        .toLowerCase() || null;

    const aliasTarget =
      modelMapping?.get(id) ??
      (typeof item.alias_target === "string" && item.alias_target.trim()
        ? item.alias_target.trim()
        : null);
    const isAlias = Boolean(modelMapping?.has(id) || item.alias === true);

    let sortedLevels = sortEfforts(normalizeThinkingLevels(item));
    const targetFold = aliasTarget ? foldModelId(aliasTarget) : { variant: null };
    if (
      isAlias &&
      sortedLevels.length === 0 &&
      !targetFold.variant &&
      aliasTarget &&
      realEntries.has(aliasTarget)
    ) {
      sortedLevels = sortEfforts(normalizeThinkingLevels(realEntries.get(aliasTarget)));
    }

    const isGoogleModel = resolveProtocolSpec(id, providerHint).npm === "@ai-sdk/google";
    const isImageOutput =
      item.capabilities?.image_generation === true ||
      (Array.isArray(item.output_modalities) && item.output_modalities.includes("image")) ||
      /image|imagen/i.test(id);
    const itemSupportsThinking =
      item.capabilities?.thinking === true ||
      item.supports_thinking === true ||
      item.thinking === true;

    const variants = {};
    const syntheticVariantIds = [];
    let isAliasFixed = false;

    if (!isImageOutput) {
      if (isAlias) {
        if (targetFold.variant !== null) {
          variants[targetFold.variant] = {};
          isAliasFixed = true;
        } else {
          for (const effort of sortedLevels) {
            variants[effort] = {};
          }
        }
      } else {
        const idFold = foldModelId(id);
        if (idFold.variant !== null && sortedLevels.length === 0 && itemSupportsThinking) {
          variants[idFold.variant] = {};
        } else {
          for (const effort of sortedLevels) {
            variants[effort] = {};
          }
          for (const lvl of sortedLevels) {
            if (!SYNTHETIC_EFFORT_LEVELS.has(lvl)) continue;
            const derivedId = `${id}-${lvl}`;
            if (!realEntries.has(derivedId)) {
              syntheticVariantIds.push(derivedId);
            }
          }
        }
      }
    }

    if (!isImageOutput && isGoogleModel) {
      if (isAlias) {
        if (isAliasFixed) {
          if (targetFold.variant === "xhigh") {
            xhighGeminiModels.add(id);
          }
        } else if (sortedLevels.includes("xhigh")) {
          xhighGeminiModels.add(id);
        }
      } else if (sortedLevels.includes("xhigh")) {
        xhighGeminiModels.add(id);
        const syntheticXhighId = `${id}-xhigh`;
        if (syntheticVariantIds.includes(syntheticXhighId)) {
          xhighGeminiModels.add(syntheticXhighId);
        }
      }
    }

    let displayName = cleanDisplayName(rawDisplayName(item), id, false);
    if (!displayName) {
      displayName = titleCaseModelId(id);
    }

    const recordMeta = (modelId, meta) => {
      if (meta.quotaGroup) {
        modelQuotaGroupMap.set(modelId, meta.quotaGroup);
      }
      modelMetadataMap.set(modelId, meta);
    };

    models[id] = buildSingleModelEntry({
      id,
      displayName,
      primary: item,
      fallbackItem: {},
      variants,
      supportsThinkingExtra: !isImageOutput && sortedLevels.length > 0,
      root,
      providerHint,
    });
    recordMeta(id, {
      quotaGroup: quotaGroup || null,
      thinkingLevels: sortedLevels,
      defaultThinkingLevel,
      provider: providerHint || null,
      syntheticVariantIds,
      ...(isAlias
        ? {
            isAlias: true,
            aliasTarget: aliasTarget || null,
            isAliasFixed,
          }
        : {}),
    });

    if (!foldEffortVariants) {
      for (const derivedId of syntheticVariantIds) {
        if (models[derivedId]) continue;
        const level = derivedId.slice(id.length + 1);
        const levelLabel = formatEffortLabel(level);
        const derivedDisplayName = `${displayName} (${levelLabel})`;
        models[derivedId] = buildSingleModelEntry({
          id: derivedId,
          displayName: derivedDisplayName,
          primary: item,
          fallbackItem: {},
          variants: { [level]: {} },
          supportsThinkingExtra: true,
          root,
          providerHint,
        });
        recordMeta(derivedId, {
          quotaGroup: quotaGroup || null,
          thinkingLevels: [],
          defaultThinkingLevel: null,
          provider: providerHint || null,
          baseId: id,
          isSynthetic: true,
        });
      }
    }
  }

  return { models, xhighGeminiModels, modelQuotaGroupMap, modelMetadataMap };
}

async function classifyPublicFailure(res) {
  if (res.status === 401 || res.status === 403) {
    await res.body?.cancel?.().catch(() => {});
    return { status: "auth_error", httpStatus: res.status };
  }
  if (res.status === 400) {
    try {
      const data = await res.json();
      const errObj = data?.error;
      const msg = typeof errObj?.message === "string" ? errObj.message : "";
      const hasApiKeyInvalid =
        Array.isArray(errObj?.details) &&
        errObj.details.some((d) => d && typeof d === "object" && d.reason === "API_KEY_INVALID");
      if (hasApiKeyInvalid && !/^\s*(?:Authentication failed:\s*)?upstream\b/i.test(msg)) {
        return { status: "auth_error", httpStatus: 400 };
      }
    } catch {
      // ignore parse error
    }
    return { status: "error" };
  }
  await res.body?.cancel?.().catch(() => {});
  if (res.status === 404 || res.status === 405 || res.status === 501) {
    return { status: "unsupported" };
  }
  return { status: "error" };
}

async function fetchPublicModelMap(url, headers, fetchImpl, signal, timeoutMs = 5000, sourceKind = "v1") {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  const combined = signal ? AbortSignal.any([signal, ctl.signal]) : ctl.signal;
  try {
    const res = await fetchImpl(url, { method: "GET", headers, signal: combined });
    if (!res.ok) return await classifyPublicFailure(res);
    const data = await res.json();
    const entries = extractModelEntries(data, sourceKind);
    if (!entries) return { status: "error" };
    return { status: "ok", entries, empty: entries.size === 0 };
  } catch {
    return { status: "error" };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchBetaModelsPaginated(baseBetaUrl, headers, fetchImpl, signal, timeoutMs = 5000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  const combined = signal ? AbortSignal.any([signal, ctl.signal]) : ctl.signal;
  try {
    const merged = new Map();
    const seenTokens = new Set();
    let pageToken = "";

    for (let page = 0; page < MAX_BETA_PAGES; page++) {
      const url = new URL(baseBetaUrl);
      url.searchParams.set("pageSize", "1000");
      if (pageToken) {
        url.searchParams.set("pageToken", pageToken);
      }
      const res = await fetchImpl(url.toString(), { method: "GET", headers, signal: combined });
      if (!res.ok) return await classifyPublicFailure(res);
      const data = await res.json();
      const pageEntries = extractModelEntries(data, "beta");
      if (!pageEntries) return { status: "error" };
      for (const [id, item] of pageEntries.entries()) {
        merged.set(id, item);
      }
      const nextToken =
        typeof data?.nextPageToken === "string" ? data.nextPageToken.trim() : "";
      if (!nextToken) {
        return { status: "ok", entries: merged, empty: merged.size === 0 };
      }
      if (seenTokens.has(nextToken)) {
        return { status: "error" };
      }
      seenTokens.add(nextToken);
      pageToken = nextToken;
    }

    return { status: "error" };
  } catch {
    return { status: "error" };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchAdminModelsRaw(authOpts, fetchImpl, signal, timeoutMs) {
  try {
    const res = await adminFetch("/api/models", {
      baseUrl: authOpts.baseUrl,
      adminUsername: authOpts.adminUsername,
      adminPassword: authOpts.adminPassword,
      method: "GET",
      fetchImpl,
      signal,
      timeoutMs,
    });
    if (!res.ok) {
      await res.body?.cancel?.().catch(() => {});
      return null;
    }
    const data = await res.json();
    const map = extractModelEntries(data, "admin");
    if (!map) return null;
    return { entries: map, validEmpty: map.size === 0 };
  } catch {
    return null;
  }
}

function storeEmptyModelCache(scopeKey, root, nowFn) {
  modelCache.set(scopeKey, {
    rawEntries: new Map(),
    modelMapping: null,
    xhighGeminiModels: new Set(),
    modelQuotaGroupMap: new Map(),
    modelMetadataMap: new Map(),
    byMode: {
      folded: {},
      unfolded: {},
    },
    discoveredAt: nowFn(),
  });
  latestScopeByRoot.set(root, scopeKey);
}

async function discoverModelsLive(authOpts, opts = {}) {
  const root = normalizeBaseUrl(authOpts?.baseUrl);
  const apiKey = typeof authOpts?.apiKey === "string" ? authOpts.apiKey.trim() : "";
  const adminUsername = authOpts?.adminUsername || "admin";
  const adminPassword = authOpts?.adminPassword || "";
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 5000;
  const signal = opts.signal;
  const nowFn = typeof opts.nowFn === "function" ? opts.nowFn : Date.now;
  const scopeKey = buildAuthScopeKey({
    baseUrl: root,
    apiKey,
    adminUsername,
    adminPassword,
  });

  if (typeof fetchImpl !== "function") return null;

  // 1. Primary source: Admin GET /api/models
  const adminResult = await fetchAdminModelsRaw(
    { baseUrl: root, adminUsername, adminPassword },
    fetchImpl,
    signal,
    timeoutMs,
  );

  if (adminResult?.validEmpty) {
    storeEmptyModelCache(scopeKey, root, nowFn);
    return {};
  }

  let merged = adminResult?.entries ?? null;
  let modelMapping = null;

  if (merged) {
    const settings = await fetchAdminSettingsCached({
      baseUrl: root,
      adminUsername,
      adminPassword,
      fetchImpl,
      signal,
      timeoutMs,
      nowFn,
    });
    modelMapping = settings?.modelMapping ?? null;
  }

  // 2. Fallback: Public GET /v1/models and GET /v1beta/models
  if (!merged) {
    const v1Headers = {
      accept: "application/json",
      ...(apiKey ? { authorization: `Bearer ${apiKey}`, "x-api-key": apiKey } : {}),
    };
    const betaHeaders = {
      accept: "application/json",
      ...(apiKey ? { "x-goog-api-key": apiKey, authorization: `Bearer ${apiKey}` } : {}),
    };

    const [v1Res, betaRes] = await Promise.all([
      fetchPublicModelMap(`${root}/v1/models`, v1Headers, fetchImpl, signal, timeoutMs, "v1"),
      fetchBetaModelsPaginated(`${root}/v1beta/models`, betaHeaders, fetchImpl, signal, timeoutMs),
    ]);

    const anyOk = v1Res.status === "ok" || betaRes.status === "ok";
    if (!anyOk) {
      if (v1Res.status === "auth_error" || betaRes.status === "auth_error") {
        const err = new Error("Antigravity2API public API key was rejected");
        err.signIn = "expired";
        throw err;
      }
      return null;
    }

    merged = new Map();
    if (betaRes.status === "ok") {
      for (const [id, item] of betaRes.entries.entries()) {
        merged.set(id, { ...item });
      }
    }
    if (v1Res.status === "ok") {
      for (const [id, item] of v1Res.entries.entries()) {
        const prev = merged.get(id);
        merged.set(id, prev ? { ...prev, ...item } : { ...item });
      }
    }

    if (merged.size === 0) {
      const v1Clean = v1Res.status === "ok" || v1Res.status === "unsupported";
      const betaClean = betaRes.status === "ok" || betaRes.status === "unsupported";
      if (v1Clean && betaClean) {
        storeEmptyModelCache(scopeKey, root, nowFn);
        return {};
      }
      return null;
    }
  }

  if (!merged || merged.size === 0) return null;

  const foldEffortVariants = Boolean(opts.foldEffortVariants);
  const { models, xhighGeminiModels, modelQuotaGroupMap, modelMetadataMap } =
    buildModelsFromRawEntries(merged, root, { foldEffortVariants, modelMapping });

  modelCache.set(scopeKey, {
    rawEntries: merged,
    modelMapping,
    xhighGeminiModels,
    modelQuotaGroupMap,
    modelMetadataMap,
    byMode: {
      [foldEffortVariants ? "folded" : "unfolded"]: models,
    },
    discoveredAt: nowFn(),
  });
  latestScopeByRoot.set(root, scopeKey);
  return models;
}

function resolveCacheEntry(baseUrlOrScope) {
  if (typeof baseUrlOrScope === "string") {
    const root = normalizeBaseUrl(baseUrlOrScope);
    const direct = modelCache.get(buildAuthScopeKey(root));
    if (direct) return { entry: direct, root };
    const latestKey = latestScopeByRoot.get(root);
    return { entry: latestKey ? modelCache.get(latestKey) : undefined, root };
  }
  const root = normalizeBaseUrl(baseUrlOrScope?.baseUrl);
  return { entry: modelCache.get(buildAuthScopeKey(baseUrlOrScope)), root };
}

function resolveEntryModels(entry, root, foldEffortVariants = false) {
  if (!entry) return null;
  const modeKey = foldEffortVariants ? "folded" : "unfolded";
  if (entry.byMode?.[modeKey]) {
    return entry.byMode[modeKey];
  }
  if (!entry.rawEntries) return null;
  const { models, xhighGeminiModels, modelQuotaGroupMap, modelMetadataMap } =
    buildModelsFromRawEntries(entry.rawEntries, root, {
      foldEffortVariants,
      modelMapping: entry.modelMapping ?? null,
    });
  entry.xhighGeminiModels = xhighGeminiModels;
  for (const [k, v] of modelQuotaGroupMap.entries()) {
    entry.modelQuotaGroupMap.set(k, v);
  }
  for (const [k, v] of modelMetadataMap.entries()) {
    entry.modelMetadataMap.set(k, v);
  }
  entry.byMode[modeKey] = models;
  return models;
}

export function getDiscoveredModels(baseUrlOrScope = DEFAULT_BASE_URL, opts = {}) {
  const { entry, root } = resolveCacheEntry(baseUrlOrScope);
  return resolveEntryModels(entry, root, Boolean(opts?.foldEffortVariants));
}

export function getModelQuotaGroupMap(baseUrlOrScope = DEFAULT_BASE_URL) {
  const { entry } = resolveCacheEntry(baseUrlOrScope);
  return entry?.modelQuotaGroupMap ? new Map(entry.modelQuotaGroupMap) : new Map();
}

export function getModelMetadataMap(baseUrlOrScope = DEFAULT_BASE_URL) {
  const { entry } = resolveCacheEntry(baseUrlOrScope);
  return entry?.modelMetadataMap ? new Map(entry.modelMetadataMap) : new Map();
}

export function isXhighGeminiModel(baseUrlOrScope, modelId) {
  const clean = String(modelId || "").trim();
  if (!clean) return false;
  const { entry } = resolveCacheEntry(baseUrlOrScope);
  if (!entry?.xhighGeminiModels) return false;
  if (entry.xhighGeminiModels.has(clean)) return true;
  const dateMatch = clean.match(/^(.+)@\d{8}$/);
  return Boolean(dateMatch && entry.xhighGeminiModels.has(dateMatch[1]));
}

export async function ensureModelsDiscovered(baseUrlOrAuth, apiKeyMaybe, opts = {}) {
  const authOpts =
    baseUrlOrAuth && typeof baseUrlOrAuth === "object"
      ? {
          baseUrl: normalizeBaseUrl(baseUrlOrAuth.baseUrl),
          apiKey: baseUrlOrAuth.apiKey || "",
          adminUsername: baseUrlOrAuth.adminUsername || "admin",
          adminPassword: baseUrlOrAuth.adminPassword || "",
        }
      : {
          baseUrl: normalizeBaseUrl(baseUrlOrAuth),
          apiKey: typeof apiKeyMaybe === "string" ? apiKeyMaybe : "",
          adminUsername: opts.adminUsername || "admin",
          adminPassword: opts.adminPassword || "",
        };

  const scopeKey = buildAuthScopeKey(authOpts);
  const foldEffortVariants = Boolean(opts?.foldEffortVariants);
  const nowFn = typeof opts.nowFn === "function" ? opts.nowFn : Date.now;
  const ttlMs =
    typeof opts.cacheTtlMs === "number" && Number.isFinite(opts.cacheTtlMs) && opts.cacheTtlMs >= 0
      ? opts.cacheTtlMs
      : MODEL_CACHE_TTL_MS;

  const existing = modelCache.get(scopeKey);
  if (existing && nowFn() - existing.discoveredAt < ttlMs) {
    return resolveEntryModels(existing, authOpts.baseUrl, foldEffortVariants);
  }

  if (inFlightDiscovery.has(scopeKey)) {
    await inFlightDiscovery.get(scopeKey);
    const updated = modelCache.get(scopeKey);
    return updated ? resolveEntryModels(updated, authOpts.baseUrl, foldEffortVariants) : null;
  }

  const promise = (async () => {
    try {
      const res = await discoverModelsLive(authOpts, {
        fetchImpl: opts.fetchImpl,
        signal: opts.signal,
        timeoutMs: opts.timeoutMs ?? 3000,
        foldEffortVariants,
        nowFn,
      });
      if (res !== null) return res;
      return existing ? resolveEntryModels(existing, authOpts.baseUrl, foldEffortVariants) : null;
    } catch {
      return existing ? resolveEntryModels(existing, authOpts.baseUrl, foldEffortVariants) : null;
    } finally {
      inFlightDiscovery.delete(scopeKey);
    }
  })();

  inFlightDiscovery.set(scopeKey, promise);
  return promise;
}

export async function reconcileModels(provider, ctx = {}, deps = {}) {
  const { auth, signal } = ctx;
  const fetchImpl = deps.fetchImpl ?? globalThis.fetch;
  const foldEffortVariants = Boolean(deps.foldEffortVariants ?? ctx.foldEffortVariants ?? false);
  const fallbackBaseUrl =
    deps.defaultBaseUrl ??
    (typeof provider?.api === "string" && provider.api.trim()
      ? normalizeBaseUrl(provider.api)
      : DEFAULT_BASE_URL);
  const resolved = resolveAuth(auth, { defaultBaseUrl: fallbackBaseUrl });

  const discovered = await discoverModelsLive(resolved, {
    fetchImpl,
    signal,
    timeoutMs: deps.timeoutMs ?? 5000,
    foldEffortVariants,
    nowFn: deps.nowFn,
  });

  if (discovered) {
    return discovered;
  }

  const cached = getDiscoveredModels(resolved, { foldEffortVariants });
  const fallbackBase =
    cached && Object.keys(cached).length > 0
      ? cached
      : provider?.models && Object.keys(provider.models).length > 0
        ? provider.models
        : {};
  const fallback = { ...fallbackBase };
  fallback[Symbol.for("magpie.fellBack")] = true;
  return fallback;
}
