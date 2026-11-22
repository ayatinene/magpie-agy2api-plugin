import {
  DEFAULT_BASE_URL,
  adminFetch,
  normalizeBaseUrl,
  resolveAuth,
} from "./auth.mjs";

export { DEFAULT_BASE_URL, normalizeBaseUrl, resolveAuth };

const MODALITIES = ["text", "image", "audio", "video", "pdf"];
const EFFORT_ORDER = ["minimal", "low", "medium", "high", "xhigh", "max"];
const EFFORT_SUFFIX_RE = /-(minimal|low|medium|high|xhigh|max)$/i;
const DISPLAY_SUFFIX_RE = /\s*\((?:minimal|low|medium|high|xhigh|max)\)\s*$/i;
const STANDARD_VIDEO_MIME_RE =
  /^video\/(mp4|webm|quicktime|x-matroska|mpeg|ogg|3gpp|x-msvideo|avi|mov|x-flv|wmv|mp2t|h264|hevc)(?:;.*)?$/i;
const STANDARD_AUDIO_MIME_RE = /^audio\/[a-z0-9.+-]+(?:;.*)?$/i;
const STANDARD_IMAGE_MIME_RE = /^image\/[a-z0-9.+-]+(?:;.*)?$/i;

const modelCache = new Map();
const inFlightDiscovery = new Map();

export function clearModelCache() {
  modelCache.clear();
  inFlightDiscovery.clear();
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
  const raw = item?.thinking_levels ?? item?.supported_reasoning_levels ?? [];
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
    if (caps.audio === true) set.add("audio");
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

  if (prov === "MODEL_PROVIDER_ANTHROPIC" || lower.startsWith("claude")) {
    return { npm: "@ai-sdk/anthropic", apiPath: "/v1", family: "Claude" };
  }
  if (prov === "MODEL_PROVIDER_GOOGLE" || lower.startsWith("gemini") || lower.startsWith("imagen")) {
    return { npm: "@ai-sdk/google", apiPath: "/v1beta", family: "Gemini" };
  }
  if (prov === "MODEL_PROVIDER_OPENAI" || lower.startsWith("gpt")) {
    return { npm: "@ai-sdk/openai-compatible", apiPath: "/v1", family: "GPT" };
  }
  const family = titleCaseModelId(lower.split("-")[0] || "OpenAI");
  return { npm: "@ai-sdk/openai-compatible", apiPath: "/v1", family };
}

function extractModelEntries(payload) {
  const list = Array.isArray(payload?.models)
    ? payload.models
    : Array.isArray(payload?.data)
      ? payload.data
      : Array.isArray(payload)
        ? payload
        : [];
  const map = new Map();
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const raw = item.id ?? item.name ?? item.model ?? "";
    if (typeof raw !== "string" || !raw.trim()) continue;
    const clean = raw.trim().replace(/^models\//, "");
    map.set(clean, item);
  }
  return map;
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
    ) ?? 128000;

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
    ) ?? 65536;

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
  const outputModalities = isImageOutput ? ["text", "image"] : ["text"];

  const supportsThinking =
    primary.capabilities?.thinking === true ||
    primary.supports_thinking === true ||
    primary.thinking === true ||
    fallbackItem.capabilities?.thinking === true ||
    supportsThinkingExtra;
  const reasoning = supportsThinking || Object.keys(variants).length > 0;

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
      toolcall: true,
      input: toCapabilityModalities(inputModalities),
      output: toCapabilityModalities(outputModalities),
      interleaved: false,
    },
    release_date: "",
    variants,
  };
}

export function buildModelsFromRawEntries(rawEntries, baseUrl = DEFAULT_BASE_URL, opts = {}) {
  const { foldEffortVariants = false } = opts;
  const root = normalizeBaseUrl(baseUrl);
  const grouped = new Map();

  for (const [rawId, item] of rawEntries.entries()) {
    const cleanRawId = String(rawId || "").trim().replace(/^models\//, "");
    const { baseId, variant } = foldModelId(cleanRawId);
    if (!baseId) continue;
    let bucket = grouped.get(baseId);
    if (!bucket) {
      bucket = {
        baseItem: null,
        levels: new Set(),
        variantEntries: [],
        variantMap: new Map(),
      };
      grouped.set(baseId, bucket);
    }
    for (const lvl of normalizeThinkingLevels(item)) {
      bucket.levels.add(lvl);
    }
    if (variant) {
      bucket.levels.add(variant);
      bucket.variantEntries.push({ rawId: cleanRawId, variant, item });
      bucket.variantMap.set(variant, { rawId: cleanRawId, item });
    } else {
      bucket.baseItem = item;
    }
  }

  const models = {};
  const xhighGeminiModels = new Set();
  const modelQuotaGroupMap = new Map();
  const modelMetadataMap = new Map();

  for (const [baseId, bucket] of grouped.entries()) {
    const variantItems = bucket.variantEntries.map((e) => e.item);
    const primary = bucket.baseItem ?? variantItems[0] ?? {};
    const fallbackItem = variantItems[0] ?? {};
    const providerHint = String(primary.provider ?? fallbackItem.provider ?? "").trim();
    const quotaGroup = String(primary.quota_group ?? fallbackItem.quota_group ?? "").trim();
    const defaultThinkingLevel =
      String(
        primary.default_thinking_level ??
          primary.default_reasoning_level ??
          fallbackItem.default_thinking_level ??
          fallbackItem.default_reasoning_level ??
          "",
      )
        .trim()
        .toLowerCase() || null;

    const sortedLevels = sortEfforts([...bucket.levels]);

    const isGoogleModel =
      providerHint.toUpperCase() === "MODEL_PROVIDER_GOOGLE" ||
      baseId.toLowerCase().startsWith("gemini");
    if (isGoogleModel && sortedLevels.includes("xhigh")) {
      xhighGeminiModels.add(baseId);
    }

    let baseDisplayName = cleanDisplayName(
      primary.name ?? primary.display_name ?? primary.displayName,
      baseId,
      !bucket.baseItem,
    );
    if (!baseDisplayName && bucket.baseItem) {
      baseDisplayName = cleanDisplayName(
        fallbackItem.name ?? fallbackItem.display_name ?? fallbackItem.displayName,
        baseId,
        true,
      );
    }
    if (!baseDisplayName) {
      baseDisplayName = titleCaseModelId(baseId);
    }

    const variants = {};
    for (const effort of sortedLevels) {
      variants[effort] = {};
    }

    const recordMeta = (modelId, itemQuotaGroup) => {
      const qg = String(itemQuotaGroup || quotaGroup || "").trim();
      if (qg) {
        modelQuotaGroupMap.set(modelId, qg);
      }
      modelMetadataMap.set(modelId, {
        quotaGroup: qg || null,
        thinkingLevels: sortedLevels,
        defaultThinkingLevel,
        provider: providerHint || null,
      });
    };

    if (foldEffortVariants || bucket.baseItem) {
      models[baseId] = buildSingleModelEntry({
        id: baseId,
        displayName: baseDisplayName,
        primary,
        fallbackItem,
        variants,
        supportsThinkingExtra:
          sortedLevels.length > 0 || variantItems.some((it) => it?.supports_thinking === true),
        root,
        providerHint,
      });
      recordMeta(baseId, primary.quota_group);
    }

    if (!foldEffortVariants) {
      const baseFallback = bucket.baseItem ?? {};
      const emitted = new Set();

      for (const { rawId, item } of bucket.variantEntries) {
        let displayName = cleanDisplayName(
          item.name ?? item.display_name ?? item.displayName,
          rawId,
          false,
        );
        if (!displayName) {
          displayName = titleCaseModelId(rawId);
        }

        models[rawId] = buildSingleModelEntry({
          id: rawId,
          displayName,
          primary: item,
          fallbackItem: baseFallback,
          variants: {},
          supportsThinkingExtra: true,
          root,
          providerHint: item.provider || providerHint,
        });
        recordMeta(rawId, item.quota_group ?? quotaGroup);
        emitted.add(rawId);
      }

      if (sortedLevels.length >= 2) {
        for (const level of sortedLevels) {
          const derivedId = `${baseId}-${level}`;
          if (emitted.has(derivedId) || models[derivedId]) continue;
          const levelLabel = formatEffortLabel(level);
          const derivedDisplayName = `${baseDisplayName} (${levelLabel})`;
          models[derivedId] = buildSingleModelEntry({
            id: derivedId,
            displayName: derivedDisplayName,
            primary,
            fallbackItem: baseFallback,
            variants: {},
            supportsThinkingExtra: true,
            root,
            providerHint,
          });
          recordMeta(derivedId, quotaGroup);
          emitted.add(derivedId);
        }
      }
    }
  }

  return { models, xhighGeminiModels, modelQuotaGroupMap, modelMetadataMap };
}

async function fetchPublicModelMap(url, headers, fetchImpl, signal, timeoutMs = 5000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  const combined = signal ? AbortSignal.any([signal, ctl.signal]) : ctl.signal;
  try {
    const res = await fetchImpl(url, { method: "GET", headers, signal: combined });
    if (!res.ok) return null;
    const data = await res.json();
    return extractModelEntries(data);
  } catch {
    return null;
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
    if (!res.ok) return null;
    const data = await res.json();
    const map = extractModelEntries(data);
    return map.size > 0 ? map : null;
  } catch {
    return null;
  }
}

async function discoverModelsLive(authOpts, opts = {}) {
  const root = normalizeBaseUrl(authOpts?.baseUrl);
  const apiKey = typeof authOpts?.apiKey === "string" ? authOpts.apiKey.trim() : "";
  const adminUsername = authOpts?.adminUsername || "admin";
  const adminPassword = authOpts?.adminPassword || "";
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 5000;
  const signal = opts.signal;

  if (typeof fetchImpl !== "function") return null;

  // 1. Primary source: Admin GET /api/models
  let merged = await fetchAdminModelsRaw(
    { baseUrl: root, adminUsername, adminPassword },
    fetchImpl,
    signal,
    timeoutMs,
  );

  // 2. Fallback: Public GET /v1/models and GET /v1beta/models
  if (!merged || merged.size === 0) {
    const v1Headers = {
      accept: "application/json",
      ...(apiKey ? { authorization: `Bearer ${apiKey}`, "x-api-key": apiKey } : {}),
    };
    const betaHeaders = {
      accept: "application/json",
      ...(apiKey ? { "x-goog-api-key": apiKey, authorization: `Bearer ${apiKey}` } : {}),
    };

    const [v1Map, betaMap] = await Promise.all([
      fetchPublicModelMap(`${root}/v1/models`, v1Headers, fetchImpl, signal, timeoutMs),
      fetchPublicModelMap(`${root}/v1beta/models`, betaHeaders, fetchImpl, signal, timeoutMs),
    ]);

    if (!v1Map && !betaMap) return null;

    merged = new Map();
    if (betaMap) {
      for (const [id, item] of betaMap.entries()) {
        merged.set(id, { ...item });
      }
    }
    if (v1Map) {
      for (const [id, item] of v1Map.entries()) {
        const prev = merged.get(id);
        merged.set(id, prev ? { ...prev, ...item } : { ...item });
      }
    }
  }

  if (!merged || merged.size === 0) return null;

  const foldEffortVariants = Boolean(opts.foldEffortVariants);
  const { models, xhighGeminiModels, modelQuotaGroupMap, modelMetadataMap } =
    buildModelsFromRawEntries(merged, root, { foldEffortVariants });
  if (Object.keys(models).length === 0) return null;

  modelCache.set(root, {
    rawEntries: merged,
    xhighGeminiModels,
    modelQuotaGroupMap,
    modelMetadataMap,
    byMode: {
      [foldEffortVariants ? "folded" : "unfolded"]: models,
    },
    discoveredAt: Date.now(),
  });
  return models;
}

function resolveEntryModels(entry, root, foldEffortVariants = false) {
  if (!entry) return null;
  const modeKey = foldEffortVariants ? "folded" : "unfolded";
  if (entry.byMode?.[modeKey]) {
    return entry.byMode[modeKey];
  }
  if (!entry.rawEntries) return null;
  const { models, xhighGeminiModels, modelQuotaGroupMap, modelMetadataMap } =
    buildModelsFromRawEntries(entry.rawEntries, root, { foldEffortVariants });
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

export function getDiscoveredModels(baseUrl = DEFAULT_BASE_URL, opts = {}) {
  const root = normalizeBaseUrl(baseUrl);
  const entry = modelCache.get(root);
  return resolveEntryModels(entry, root, Boolean(opts?.foldEffortVariants));
}

export function getModelQuotaGroupMap(baseUrl = DEFAULT_BASE_URL) {
  const root = normalizeBaseUrl(baseUrl);
  const entry = modelCache.get(root);
  return entry?.modelQuotaGroupMap ? new Map(entry.modelQuotaGroupMap) : new Map();
}

export function getModelMetadataMap(baseUrl = DEFAULT_BASE_URL) {
  const root = normalizeBaseUrl(baseUrl);
  const entry = modelCache.get(root);
  return entry?.modelMetadataMap ? new Map(entry.modelMetadataMap) : new Map();
}

export function isXhighGeminiModel(baseUrl, modelId) {
  const clean = String(modelId || "").split("@")[0].trim();
  if (!clean) return false;
  const entry = modelCache.get(normalizeBaseUrl(baseUrl));
  if (!entry?.xhighGeminiModels) return false;
  if (entry.xhighGeminiModels.has(clean)) return true;
  const { baseId, variant } = foldModelId(clean);
  return variant === "xhigh" && entry.xhighGeminiModels.has(baseId);
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

  const root = authOpts.baseUrl;
  const foldEffortVariants = Boolean(opts?.foldEffortVariants);
  const existing = modelCache.get(root);
  if (existing) return resolveEntryModels(existing, root, foldEffortVariants);

  if (inFlightDiscovery.has(root)) {
    await inFlightDiscovery.get(root);
    return getDiscoveredModels(root, { foldEffortVariants });
  }

  const promise = (async () => {
    try {
      return await discoverModelsLive(authOpts, {
        fetchImpl: opts.fetchImpl,
        signal: opts.signal,
        timeoutMs: opts.timeoutMs ?? 3000,
        foldEffortVariants,
      });
    } catch {
      return null;
    } finally {
      inFlightDiscovery.delete(root);
    }
  })();

  inFlightDiscovery.set(root, promise);
  return promise;
}

export async function reconcileModels(provider, ctx = {}, deps = {}) {
  const { auth, signal } = ctx;
  const fetchImpl = deps.fetchImpl ?? globalThis.fetch;
  const foldEffortVariants = Boolean(deps.foldEffortVariants ?? ctx.foldEffortVariants ?? false);
  const resolved = resolveAuth(auth);

  const discovered = await discoverModelsLive(resolved, {
    fetchImpl,
    signal,
    timeoutMs: deps.timeoutMs ?? 5000,
    foldEffortVariants,
  });

  if (discovered) {
    return discovered;
  }

  const cached = getDiscoveredModels(resolved.baseUrl, { foldEffortVariants });
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
