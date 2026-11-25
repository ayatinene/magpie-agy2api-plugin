import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { DEFAULT_BASE_URL, normalizeBaseUrl, resolveAuth } from "./auth.mjs";
import {
  ensureModelsDiscovered,
  foldModelId,
  getDiscoveredModels,
  getModelMetadataMap,
  resolveProtocolSpec,
} from "./models.mjs";
import { getCachedModelQuotaWindow } from "./quota.mjs";
import {
  MIN_RELAY_SECRET_LEN,
  RELAY_FIELD,
  applyEffortToBody,
  signRelayPayload,
} from "./relay-crypto.mjs";
import { RELAY_SECRET } from "./relay-secret.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.resolve(__dirname, "..");

export const DEFAULT_AUX_TTL_MS = 10 * 60 * 1000;
export const DEFAULT_AUX_MIN_BODY_BYTES = 32 * 1024;
export const DEFAULT_AUX_MAX_OUTPUT_TOKENS = 8192;
export const MAX_MAIN_SESSION_ENTRIES = 256;
export const MAX_AUX_DIAGNOSTICS = 128;
export const AUX_TICKET_TTL_MS = 60 * 1000;
export const MAX_RELAY_BODY_BYTES = 6 * 1024 * 1024;
export const AUX_CONTEXT_PROTOCOL_OVERHEAD_TOKENS = 16_384;
const PLUGINS_JSON_CACHE_MS = 1000;

export const EFFORT_RANK = Object.freeze({
  minimal: 0,
  low: 1,
  medium: 2,
  high: 3,
  xhigh: 4,
  max: 5,
});

export const EFFORT_TO_BUDGET = Object.freeze({
  minimal: 512,
  low: 1024,
  medium: 8192,
  high: 16384,
  xhigh: 24576,
  max: 32768,
});

const VALID_POLICIES = new Set(["keep", "current_low", "fallback_model"]);

const AUX_PURPOSE_VALUES = new Set([
  "project_memory_extract",
  "project_memory_dream",
  "target_completion_verification",
  "memory_extract",
  "aux",
  "auxiliary",
  "title",
  "session_title",
  "thread_title",
]);

const MAIN_PURPOSE_VALUES = new Set(["main_turn", "compact"]);

let inMemoryRelaySecret = "";
let runtimeContext = {
  directory: "",
  magpie: null,
  staticOptions: null,
  authScope: null,
  authScopeAmbiguous: false,
  defaultBaseUrl: DEFAULT_BASE_URL,
};
let pluginsJsonCache = {
  path: "",
  checkedAtMs: 0,
  mtimeMs: -1,
  size: -1,
  options: null,
};
let pluginAuthCache = {
  dir: "",
  defaultBaseUrl: DEFAULT_BASE_URL,
  stamp: "",
  status: "none",
  scope: null,
};
let settingsUiCache = {
  path: "",
  mtimeMs: -1,
  size: -1,
  exists: false,
  chosenOpts: null,
};

let nextMainSeq = 0;
let auxRouterGeneration = 0;

// Keyed by `${originScope}\0${sessionId}`
const mainSessionMap = new Map();
// Pending main commits from hooks.mjs so fetch.mjs shares originScope and deduplicates
const pendingMainMap = new Map();
// Dual-keyed isolation tickets
const ticketsByDigest = new Map(); // `${sessionId}\0${digest}` -> ticket[]
const ticketsByModel = new Map(); // `${sessionId}\0${bareModel}` -> ticket[]
// Ring buffer of sanitized diagnostics
const auxDiagnostics = [];
// Extensible adapters registered via registerAuxAdapter
const customAdapters = [];

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function isPlainObject(val) {
  return Boolean(val) && typeof val === "object" && !Array.isArray(val);
}

export function stripModelPrefix(rawModel) {
  let clean = typeof rawModel === "string" ? rawModel.trim() : "";
  if (!clean) return "";
  if (clean.startsWith("agy2api/")) clean = clean.slice("agy2api/".length).trim();
  else if (clean.startsWith("agy2api-plugin/")) clean = clean.slice("agy2api-plugin/".length).trim();
  else if (clean.startsWith("auto/")) clean = clean.slice("auto/".length).trim();
  if (clean.startsWith("models/")) clean = clean.slice("models/".length).trim();
  return clean;
}

function isExplicitForeignProviderModel(rawModel) {
  const raw = typeof rawModel === "string" ? rawModel.trim() : "";
  const slashIdx = raw.indexOf("/");
  if (slashIdx <= 0) return false;
  const prefix = raw.slice(0, slashIdx).trim().toLowerCase();
  return !["agy2api", "agy2api-plugin", "auto", "group", "models"].includes(prefix);
}

function isCatalogKnownNonAgyModel(authScope, rawModel, bareModel) {
  const raw = typeof rawModel === "string" ? rawModel.trim().toLowerCase() : "";
  if (raw.startsWith("agy2api/") || raw.startsWith("agy2api-plugin/")) {
    return false;
  }
  const models =
    getDiscoveredModels(authScope) ?? getDiscoveredModels(authScope, { foldEffortVariants: true });
  if (!models || Object.keys(models).length === 0) {
    return false;
  }
  if (!bareModel) return false;
  const baseId = foldModelId(bareModel).baseId;
  return !(bareModel in models) && !(baseId in models);
}

export function normalizeEffort(raw) {
  if (typeof raw !== "string") return null;
  const norm = raw.trim().toLowerCase().replace(/^thinking_level_/, "");
  if (norm === "none") return "none";
  return Object.prototype.hasOwnProperty.call(EFFORT_RANK, norm) ? norm : null;
}

export function budgetTokensToEffort(budgetTokens) {
  if (typeof budgetTokens !== "number" || !Number.isFinite(budgetTokens)) return null;
  if (budgetTokens < 0) return null;
  if (budgetTokens === 0) return "none";
  if (budgetTokens <= 1024) return "low";
  if (budgetTokens <= 8192) return "medium";
  if (budgetTokens <= 16384) return "high";
  return "xhigh";
}

function firstPositiveInt(...candidates) {
  for (const val of candidates) {
    if (typeof val === "number" && Number.isFinite(val) && val > 0) {
      return val;
    }
  }
  return null;
}

export function resolveRequestEffortAndMaxOutput(protocol, parsedBody, headerEffort) {
  const hdrEffort = normalizeEffort(headerEffort);

  if (!isPlainObject(parsedBody)) {
    return { effort: null, rank: null, maxOutputTokens: null, disabled: false, slot: null, budgetTokens: null };
  }

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

// ==================== Secret Management ====================

function readDiskRelaySecret(secretPath) {
  try {
    const raw = fs.readFileSync(secretPath, "utf8");
    const match = raw.match(/export\s+const\s+RELAY_SECRET\s*=\s*["']([^"']+)["']/);
    if (match && match[1] && match[1].length >= 64) {
      return match[1];
    }
  } catch {
    // ignore missing/unreadable
  }
  return "";
}

export function ensureRelaySecret(opts = {}) {
  const optSecret =
    typeof opts?.relaySecret === "string" && opts.relaySecret.length >= MIN_RELAY_SECRET_LEN
      ? opts.relaySecret
      : typeof opts?.options?.relaySecret === "string" && opts.options.relaySecret.length >= MIN_RELAY_SECRET_LEN
        ? opts.options.relaySecret
        : "";
  if (optSecret) {
    return optSecret;
  }

  const targetDir = opts?.targetDir ? path.resolve(opts.targetDir) : PLUGIN_ROOT;
  const isDefaultRoot = targetDir === PLUGIN_ROOT;

  if (isDefaultRoot) {
    if (inMemoryRelaySecret.length >= 64) {
      return inMemoryRelaySecret;
    }
    if (typeof RELAY_SECRET === "string" && RELAY_SECRET.length >= 64) {
      inMemoryRelaySecret = RELAY_SECRET;
      return inMemoryRelaySecret;
    }
  } else {
    const existingDisk = readDiskRelaySecret(path.join(targetDir, "lib", "relay-secret.mjs"));
    if (existingDisk.length >= 64) {
      return existingDisk;
    }
  }

  // Never pollute a Git working tree with generated secrets
  try {
    if (fs.existsSync(path.join(targetDir, ".git"))) {
      return "";
    }
  } catch {
    return "";
  }

  const secretPath = path.join(targetDir, "lib", "relay-secret.mjs");
  const mwPath = path.join(targetDir, "middleware.mjs");
  try {
    const generated = crypto.randomBytes(32).toString("hex");
    const tmpPath = path.join(
      targetDir,
      "lib",
      `.relay-secret.mjs.tmp.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2, 8)}`,
    );
    fs.writeFileSync(tmpPath, `export const RELAY_SECRET = ${JSON.stringify(generated)};\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    fs.renameSync(tmpPath, secretPath);

    try {
      const now = new Date();
      fs.utimesSync(mwPath, now, now);
    } catch {
      // ignore if middleware.mjs missing or utimes unsupported
    }

    if (isDefaultRoot) {
      inMemoryRelaySecret = generated;
    }
    return generated;
  } catch {
    return "";
  }
}

export function clearRelaySecretCacheForTests() {
  inMemoryRelaySecret = "";
}

// ==================== Runtime Context & Live Options ====================

export function setPluginRuntimeContext(ctx = {}) {
  if (typeof ctx.directory === "string") {
    runtimeContext.directory = ctx.directory;
  }
  if (ctx.magpie !== undefined) {
    runtimeContext.magpie = ctx.magpie;
  }
  if (ctx.staticOptions !== undefined) {
    runtimeContext.staticOptions = ctx.staticOptions;
  }
  if (typeof ctx.defaultBaseUrl === "string" && ctx.defaultBaseUrl.trim()) {
    runtimeContext.defaultBaseUrl = normalizeBaseUrl(ctx.defaultBaseUrl);
  }
  if (ctx.authScope !== undefined) {
    runtimeContext.authScope = ctx.authScope;
    runtimeContext.authScopeAmbiguous = false;
  }
}

function isSameAuthScope(a, b) {
  if (!a || !b || typeof a !== "object" || typeof b !== "object") return false;
  return (
    normalizeBaseUrl(a.baseUrl || DEFAULT_BASE_URL) ===
      normalizeBaseUrl(b.baseUrl || DEFAULT_BASE_URL) &&
    String(a.apiKey || "") === String(b.apiKey || "") &&
    String(a.adminUsername || "admin") === String(b.adminUsername || "admin") &&
    String(a.adminPassword || "") === String(b.adminPassword || "")
  );
}

function hasAuthCredentials(scope) {
  return Boolean(scope && typeof scope === "object" && (scope.apiKey || scope.adminPassword));
}

function readPluginAuthScopeCached(directory, defaultBaseUrl = DEFAULT_BASE_URL) {
  if (typeof directory !== "string" || !directory.trim()) {
    return { status: "none", scope: null };
  }
  const dir = directory.trim();
  const normDefault = normalizeBaseUrl(defaultBaseUrl || DEFAULT_BASE_URL);

  const primaryPath = path.join(dir, "plugin-auth.json");
  const backupPath = path.join(dir, "plugin-auth.json.bak");
  let stamp = "";
  for (const candidate of [primaryPath, backupPath]) {
    try {
      const stat = fs.statSync(candidate);
      stamp += `${candidate}:${stat.mtimeMs}:${stat.size};`;
    } catch {
      stamp += `${candidate}:missing;`;
    }
  }
  if (
    pluginAuthCache.dir === dir &&
    pluginAuthCache.defaultBaseUrl === normDefault &&
    pluginAuthCache.stamp === stamp
  ) {
    return { status: pluginAuthCache.status, scope: pluginAuthCache.scope };
  }

  let parsed = null;
  for (const candidate of [primaryPath, backupPath]) {
    try {
      const obj = JSON.parse(fs.readFileSync(candidate, "utf8"));
      if (isPlainObject(obj)) {
        parsed = obj;
        break;
      }
    } catch {
      // try .bak read-only fallback when primary is absent or unreadable
    }
  }

  let status = "none";
  let scope = null;
  if (parsed) {
    // Match Magpie host.js accountsOf(all, "agy2api"): exact "agy2api" or "agy2api#<suffix>"
    const matchingKeys = Object.keys(parsed).filter(
      (k) => (k === "agy2api" || k.startsWith("agy2api#")) && isPlainObject(parsed[k]),
    );
    if (matchingKeys.length === 1) {
      status = "single";
      scope = resolveAuth(parsed[matchingKeys[0]], { defaultBaseUrl: normDefault });
    } else if (matchingKeys.length > 1) {
      // Multi-login scope cannot be determined before routing; never guess another account
      status = "ambiguous";
      scope = null;
    }
  }

  pluginAuthCache = {
    dir,
    defaultBaseUrl: normDefault,
    stamp,
    status,
    scope,
  };
  return { status, scope };
}

export function registerAuthScope(authScope) {
  if (!authScope || typeof authScope !== "object") return;
  const fallbackBaseUrl = runtimeContext.defaultBaseUrl || DEFAULT_BASE_URL;
  const nextScope = {
    baseUrl: normalizeBaseUrl(authScope.baseUrl || fallbackBaseUrl),
    apiKey: typeof authScope.apiKey === "string" ? authScope.apiKey.trim() : "",
    adminUsername:
      typeof authScope.adminUsername === "string" && authScope.adminUsername.trim()
        ? authScope.adminUsername.trim()
        : "admin",
    adminPassword: typeof authScope.adminPassword === "string" ? authScope.adminPassword : "",
  };
  const nextHasCreds = hasAuthCredentials(nextScope);
  const currHasCreds = hasAuthCredentials(runtimeContext.authScope);

  if (!nextHasCreds) {
    if (!runtimeContext.authScope) {
      runtimeContext.authScope = nextScope;
    }
    return;
  }

  if (currHasCreds && !isSameAuthScope(runtimeContext.authScope, nextScope)) {
    runtimeContext.authScopeAmbiguous = true;
    return;
  }

  runtimeContext.authScope = nextScope;
}

export function getRegisteredAuthScope() {
  const fallbackBaseUrl = runtimeContext.defaultBaseUrl || DEFAULT_BASE_URL;

  if (runtimeContext.directory) {
    const disk = readPluginAuthScopeCached(runtimeContext.directory, fallbackBaseUrl);
    if (disk.status === "ambiguous" || runtimeContext.authScopeAmbiguous) {
      return null;
    }
    if (disk.status === "single" && disk.scope) {
      if (
        hasAuthCredentials(runtimeContext.authScope) &&
        !isSameAuthScope(runtimeContext.authScope, disk.scope)
      ) {
        return null;
      }
      return disk.scope;
    }
    if (runtimeContext.authScope) {
      return runtimeContext.authScope;
    }
    return fallbackBaseUrl;
  }

  if (runtimeContext.authScopeAmbiguous) {
    return null;
  }
  return runtimeContext.authScope ?? fallbackBaseUrl;
}

function findPluginEntryInList(plugins) {
  if (!Array.isArray(plugins)) return null;
  let fallbackMatch = null;
  for (const entry of plugins) {
    if (!entry || typeof entry !== "object" || entry.off === true) continue;
    const spec = typeof entry.spec === "string" ? entry.spec.toLowerCase() : "";
    if (spec.includes("magpie-agy2api-plugin")) {
      return isPlainObject(entry.options) ? entry.options : null;
    }
    if (!fallbackMatch && spec.includes("agy2api")) {
      fallbackMatch = isPlainObject(entry.options) ? entry.options : null;
    }
  }
  return fallbackMatch;
}

function readPluginsJsonOptionsCached(directory, nowMs = Date.now()) {
  if (typeof directory !== "string" || !directory.trim()) return null;
  const filePath = path.join(directory.trim(), "plugins.json");
  if (
    pluginsJsonCache.path === filePath &&
    nowMs - pluginsJsonCache.checkedAtMs < PLUGINS_JSON_CACHE_MS
  ) {
    return pluginsJsonCache.options;
  }
  try {
    const stat = fs.statSync(filePath);
    if (
      pluginsJsonCache.path === filePath &&
      pluginsJsonCache.mtimeMs === stat.mtimeMs &&
      pluginsJsonCache.size === stat.size
    ) {
      pluginsJsonCache.checkedAtMs = nowMs;
      return pluginsJsonCache.options;
    }
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    const opts = findPluginEntryInList(parsed?.plugins);
    pluginsJsonCache = {
      path: filePath,
      checkedAtMs: nowMs,
      mtimeMs: stat.mtimeMs,
      size: stat.size,
      options: opts,
    };
    return opts;
  } catch {
    pluginsJsonCache = {
      path: filePath,
      checkedAtMs: nowMs,
      mtimeMs: -1,
      size: -1,
      options: null,
    };
    return null;
  }
}

function tryCoerceBool(val) {
  if (typeof val === "boolean") return val;
  if (typeof val === "string") {
    const t = val.trim().toLowerCase();
    if (t === "true") return true;
    if (t === "false") return false;
  }
  return undefined;
}

function tryCoerceNonNegNum(val) {
  if (typeof val === "number") return Number.isFinite(val) && val >= 0 ? val : undefined;
  if (typeof val === "string" && val.trim()) {
    const n = Number(val);
    return Number.isFinite(n) && n >= 0 ? n : undefined;
  }
  return undefined;
}

function tryCoerceString(val) {
  return typeof val === "string" ? val.trim() : undefined;
}

function tryCoercePolicy(val) {
  if (typeof val !== "string") return undefined;
  const norm = val.trim().toLowerCase();
  return VALID_POLICIES.has(norm) ? norm : undefined;
}

function tryCoerceEffortOpt(val) {
  const norm = normalizeEffort(val);
  return norm && norm !== "none" ? norm : undefined;
}

function readOptionValue(src, camelKey, snakeKey, coerce) {
  if (!isPlainObject(src)) return undefined;
  if (snakeKey in src) {
    const v = coerce(src[snakeKey]);
    if (v !== undefined) return v;
  }
  if (camelKey in src) {
    const v = coerce(src[camelKey]);
    if (v !== undefined) return v;
  }
  return undefined;
}

function pickFromSources(sources, camelKey, snakeKey, coerce, fallback) {
  for (const src of sources) {
    const v = readOptionValue(src, camelKey, snakeKey, coerce);
    if (v !== undefined) return v;
  }
  return fallback;
}

async function readMagpieApiOptionsSafe() {
  const m = runtimeContext.magpie;
  if (!m || typeof m.options !== "function") return null;
  try {
    const res = await Promise.resolve(m.options("agy2api"));
    return isPlainObject(res) ? res : null;
  } catch {
    return null;
  }
}

function readSettingsUiOptionsCached(directory) {
  if (typeof directory !== "string" || !directory.trim()) {
    return { exists: false, chosenOpts: null };
  }
  const filePath = path.join(directory.trim(), "settings.json");
  try {
    const stat = fs.statSync(filePath);
    if (
      settingsUiCache.path === filePath &&
      settingsUiCache.mtimeMs === stat.mtimeMs &&
      settingsUiCache.size === stat.size
    ) {
      return { exists: settingsUiCache.exists, chosenOpts: settingsUiCache.chosenOpts };
    }
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    const chosen = isPlainObject(parsed?.pluginOptions?.agy2api)
      ? parsed.pluginOptions.agy2api
      : null;
    settingsUiCache = {
      path: filePath,
      mtimeMs: stat.mtimeMs,
      size: stat.size,
      exists: true,
      chosenOpts: chosen,
    };
    return { exists: true, chosenOpts: chosen };
  } catch {
    settingsUiCache = {
      path: filePath,
      mtimeMs: -1,
      size: -1,
      exists: false,
      chosenOpts: null,
    };
    return { exists: false, chosenOpts: null };
  }
}

async function resolvePreserveCacheEffortWithSource(ctxOptions, opts = {}) {
  const nowMs = typeof opts.nowFn === "function" ? opts.nowFn() : Date.now();
  const directory = typeof opts.directory === "string" ? opts.directory : runtimeContext.directory;
  const diskOpts = opts.diskOpts !== undefined ? opts.diskOpts : readPluginsJsonOptionsCached(directory, nowMs);
  const settingsUi = opts.settingsUi !== undefined ? opts.settingsUi : readSettingsUiOptionsCached(directory);
  const uiOpts = opts.uiOpts !== undefined ? opts.uiOpts : await readMagpieApiOptionsSafe();
  const ctxObj = isPlainObject(ctxOptions) ? ctxOptions : null;
  const staticObj = isPlainObject(runtimeContext.staticOptions) ? runtimeContext.staticOptions : null;

  // Magpie host.js `optionValues("agy2api")` echoes `auth.options[].default` when `settings.json`
  // has no user-chosen override. When `settings.json` exists, use its explicit `pluginOptions.agy2api`
  // so `plugins.json` (`diskOpts` / `ctxObj`) is never masked by synthesized UI defaults.
  const taggedSources = settingsUi.exists
    ? [
        [settingsUi.chosenOpts, "provider_ui"],
        [diskOpts, "plugins_json"],
        [ctxObj, "plugins_json"],
        [staticObj, "plugins_json"],
      ]
    : [
        [diskOpts, "plugins_json"],
        [ctxObj, "plugins_json"],
        [uiOpts, "provider_ui"],
        [staticObj, "plugins_json"],
      ];

  for (const [src, preserveSource] of taggedSources) {
    const v = readOptionValue(src, "preserveCacheEffort", "preserve_cache_effort", tryCoerceBool);
    if (v !== undefined) {
      return { preserveCacheEffort: v, preserveSource };
    }
  }

  return { preserveCacheEffort: true, preserveSource: "default" };
}

export async function readLiveAuxOptions(ctxOptions, opts = {}) {
  const nowMs = typeof opts.nowFn === "function" ? opts.nowFn() : Date.now();
  const directory = typeof opts.directory === "string" ? opts.directory : runtimeContext.directory;
  const diskOpts = readPluginsJsonOptionsCached(directory, nowMs);
  const settingsUi = readSettingsUiOptionsCached(directory);
  const uiOpts = await readMagpieApiOptionsSafe();
  const ctxObj = isPlainObject(ctxOptions) ? ctxOptions : null;
  const staticObj = isPlainObject(runtimeContext.staticOptions) ? runtimeContext.staticOptions : null;

  const { preserveCacheEffort } = await resolvePreserveCacheEffortWithSource(ctxObj, {
    nowFn: () => nowMs,
    directory,
    diskOpts,
    settingsUi,
    uiOpts,
  });
  // For aux routing policy/model/effort: plugins.json > ctx.options > uiOpts > staticOptions
  const auxSources = [diskOpts, ctxObj, uiOpts, staticObj];
  const auxIncompatiblePolicy = pickFromSources(
    auxSources,
    "auxIncompatiblePolicy",
    "aux_incompatible_policy",
    tryCoercePolicy,
    "current_low",
  );
  const auxFallbackModel = pickFromSources(
    auxSources,
    "auxFallbackModel",
    "aux_fallback_model",
    tryCoerceString,
    "",
  );
  const auxFallbackEffort = pickFromSources(
    auxSources,
    "auxFallbackEffort",
    "aux_fallback_effort",
    tryCoerceEffortOpt,
    "low",
  );
  const minBodyBytes = pickFromSources(
    auxSources,
    "auxMinBodyBytes",
    "aux_min_body_bytes",
    tryCoerceNonNegNum,
    DEFAULT_AUX_MIN_BODY_BYTES,
  );
  const maxAuxOutputTokens = pickFromSources(
    auxSources,
    "auxMaxOutputTokens",
    "aux_max_output_tokens",
    tryCoerceNonNegNum,
    DEFAULT_AUX_MAX_OUTPUT_TOKENS,
  );
  const ttlSec = pickFromSources(
    auxSources,
    "auxSessionTtlSec",
    "aux_session_ttl_sec",
    tryCoerceNonNegNum,
    DEFAULT_AUX_TTL_MS / 1000,
  );
  const relaySecret = pickFromSources(
    auxSources,
    "relaySecret",
    "relay_secret",
    tryCoerceString,
    "",
  );

  return {
    preserveCacheEffort,
    auxIncompatiblePolicy,
    auxFallbackModel,
    auxFallbackEffort,
    minBodyBytes,
    maxAuxOutputTokens,
    ttlMs: ttlSec * 1000,
    relaySecret,
  };
}

/**
 * Query the effective `preserveCacheEffort` master switch and its configuration source
 * (`"provider_ui"`, `"plugins_json"`, or `"default"`).
 */
export async function getAuxMasterSwitchStatus(opts = {}) {
  return resolvePreserveCacheEffortWithSource(opts?.ctxOptions, opts);
}

// ==================== B2: Snapshot & Continuous LCP Chain ====================

function splitLeadingSystemChatOrResponses(items) {
  const leadingSystem = [];
  const turns = [];
  let seenNonSystem = false;
  for (const item of items) {
    const role = String(item?.role || "").trim().toLowerCase();
    if (!seenNonSystem && (role === "system" || role === "developer")) {
      leadingSystem.push(item);
    } else {
      seenNonSystem = true;
      turns.push(item);
    }
  }
  return { leadingSystem, turns };
}

function hasNonEmptyTools(protocol, body) {
  if (!isPlainObject(body)) return false;
  if (protocol === "gemini") {
    if (!Array.isArray(body.tools) || body.tools.length === 0) return false;
    return body.tools.some((t) => {
      if (!isPlainObject(t)) return false;
      if (Array.isArray(t.functionDeclarations) && t.functionDeclarations.length > 0) return true;
      if (Array.isArray(t.function_declarations) && t.function_declarations.length > 0) return true;
      return Object.keys(t).some(
        (k) => k !== "functionDeclarations" && k !== "function_declarations",
      );
    });
  }
  if (Array.isArray(body.tools) && body.tools.length > 0) return true;
  if (protocol === "chat" && Array.isArray(body.functions) && body.functions.length > 0) return true;
  return false;
}

function collectTurnFingerprintParts(node, state) {
  if (node === null || node === undefined) return;
  if (typeof node === "string") {
    const cleaned = node
      .replace(/<system-reminder>[\s\S]*?<\/system-reminder>/gi, "")
      .replace(/\s+/g, " ")
      .trim();
    if (cleaned) state.texts.push(cleaned);
    return;
  }
  if (Array.isArray(node)) {
    for (const item of node) {
      collectTurnFingerprintParts(item, state);
    }
    return;
  }
  if (!isPlainObject(node)) return;

  // Skip thinking/thought blocks so stripping thinking in aux branches still retains lineage
  if (node.thought === true || node.type === "thinking" || node.type === "redacted_thinking" || node.type === "reasoning") {
    return;
  }

  if (node.type === "tool_use") {
    if (typeof node.id === "string" && node.id) state.toolIds.push(`tu:${node.id}`);
    if (typeof node.name === "string" && node.name) state.toolIds.push(`tn:${node.name}`);
    if (node.input !== undefined) state.texts.push(stableStringify(node.input));
    return;
  }
  if (node.type === "tool_result") {
    if (typeof node.tool_use_id === "string" && node.tool_use_id) state.toolIds.push(`tr:${node.tool_use_id}`);
    collectTurnFingerprintParts(node.content, state);
    return;
  }
  if (isPlainObject(node.functionCall)) {
    if (typeof node.functionCall.name === "string") state.toolIds.push(`fc:${node.functionCall.name}`);
    if (node.functionCall.args !== undefined) state.texts.push(stableStringify(node.functionCall.args));
    return;
  }
  if (isPlainObject(node.functionResponse)) {
    if (typeof node.functionResponse.name === "string") state.toolIds.push(`fr:${node.functionResponse.name}`);
    if (node.functionResponse.response !== undefined) state.texts.push(stableStringify(node.functionResponse.response));
    return;
  }
  if (Array.isArray(node.tool_calls)) {
    for (const tc of node.tool_calls) {
      if (typeof tc?.id === "string" && tc.id) state.toolIds.push(`tc:${tc.id}`);
      if (typeof tc?.function?.name === "string") state.toolIds.push(`tn:${tc.function.name}`);
      if (typeof tc?.function?.arguments === "string") state.texts.push(tc.function.arguments.trim());
    }
  }
  if (typeof node.tool_call_id === "string" && node.tool_call_id) {
    state.toolIds.push(`tr:${node.tool_call_id}`);
  }
  if (typeof node.call_id === "string" && node.call_id) {
    state.toolIds.push(`cid:${node.call_id}`);
  }
  if (typeof node.name === "string" && (node.type === "function_call" || node.role === "function")) {
    state.toolIds.push(`fn:${node.name}`);
  }
  if (typeof node.arguments === "string" && node.type === "function_call") {
    state.texts.push(node.arguments.trim());
  }
  if (node.output !== undefined && node.type === "function_call_output") {
    collectTurnFingerprintParts(node.output, state);
  }
  if (typeof node.text === "string") {
    collectTurnFingerprintParts(node.text, state);
    return;
  }
  if (node.content !== undefined) {
    collectTurnFingerprintParts(node.content, state);
    return;
  }
  if (node.parts !== undefined) {
    collectTurnFingerprintParts(node.parts, state);
  }
}

function normalizeRoleForFingerprint(item) {
  const r = String(item?.role || item?.type || "").trim().toLowerCase();
  if (r === "model") return "assistant";
  if (r === "function") return "tool";
  if (r === "function_call") return "assistant";
  if (r === "function_call_output") return "tool";
  return r || "unknown";
}

function computeRawTurnFingerprint(turn) {
  const role = normalizeRoleForFingerprint(turn);
  const state = { texts: [], toolIds: [] };
  collectTurnFingerprintParts(turn, state);
  const body = `${state.texts.join("\n")}\0${state.toolIds.join(",")}`;
  if (!state.texts.length && !state.toolIds.length) {
    return sha256Hex(`${role}\0${stableStringify(turn)}`);
  }
  return sha256Hex(`${role}\0${body}`);
}

export function extractAssistantReplyFingerprint(protocol, reply) {
  if (!isPlainObject(reply)) return null;
  if (protocol === "gemini") {
    const content = reply.candidates?.[0]?.content;
    if (isPlainObject(content)) {
      return computeRawTurnFingerprint({ role: "model", parts: content.parts ?? [] });
    }
  } else if (protocol === "anthropic") {
    if (Array.isArray(reply.content) || typeof reply.content === "string") {
      return computeRawTurnFingerprint({ role: "assistant", content: reply.content });
    }
  } else if (protocol === "chat") {
    const msg = reply.choices?.[0]?.message;
    if (isPlainObject(msg)) {
      return computeRawTurnFingerprint({ role: "assistant", ...msg });
    }
  } else if (protocol === "responses") {
    if (Array.isArray(reply.output) && reply.output.length > 0) {
      // Join all non-reasoning assistant outputs for fingerprint or take first assistant message
      const msgItem = reply.output.find((o) => o?.type === "message" || o?.role === "assistant");
      if (msgItem) {
        return computeRawTurnFingerprint(msgItem);
      }
    }
  }
  return null;
}

export function extractConversationSnapshot(protocol, body, headerEffort = null) {
  const proto = typeof protocol === "string" ? protocol.trim().toLowerCase() : "";
  const effortInfo = resolveRequestEffortAndMaxOutput(proto, body, headerEffort);
  const hasTools = hasNonEmptyTools(proto, body);
  const bareModel = stripModelPrefix(body?.model || "");

  let framePayload = null;
  let turns = [];

  if (proto === "gemini" && isPlainObject(body)) {
    const sys = body.systemInstruction ?? body.system_instruction ?? null;
    const tools = hasTools ? body.tools : null;
    const toolConfig = body.toolConfig ?? body.tool_config ?? null;
    const cachedContent = body.cachedContent ?? body.cached_content ?? null;
    framePayload = ["gemini", sys, tools, toolConfig, cachedContent];
    turns = Array.isArray(body.contents) ? body.contents : [];
  } else if (proto === "anthropic" && isPlainObject(body)) {
    const sys = body.system ?? null;
    const tools = hasTools ? body.tools : null;
    const toolChoice = body.tool_choice ?? null;
    framePayload = ["anthropic", sys, tools, toolChoice, null];
    turns = Array.isArray(body.messages) ? body.messages : [];
  } else if (proto === "chat" && isPlainObject(body)) {
    const msgs = Array.isArray(body.messages) ? body.messages : [];
    const { leadingSystem, turns: rest } = splitLeadingSystemChatOrResponses(msgs);
    const tools = Array.isArray(body.tools) && body.tools.length > 0 ? body.tools : null;
    const functions = Array.isArray(body.functions) && body.functions.length > 0 ? body.functions : null;
    const toolChoice = body.tool_choice ?? null;
    const functionCall = body.function_call ?? null;
    framePayload = ["chat", leadingSystem, { tools, functions }, { toolChoice, functionCall }, null];
    turns = rest.length > 0 ? rest : msgs;
  } else if (proto === "responses" && isPlainObject(body)) {
    let leadingSystem = [];
    if (typeof body.input === "string") {
      turns = [{ type: "message", role: "user", content: body.input }];
    } else if (Array.isArray(body.input)) {
      const split = splitLeadingSystemChatOrResponses(body.input);
      leadingSystem = split.leadingSystem;
      turns = split.turns.length > 0 ? split.turns : body.input;
    }
    const tools = hasTools ? body.tools : null;
    const toolChoice = body.tool_choice ?? null;
    framePayload = ["responses", [body.instructions ?? null, leadingSystem], tools, toolChoice, null];
  } else {
    framePayload = [proto || "unknown", null, null, null, null];
  }

  const frameDigest = sha256Hex(stableStringify(framePayload));
  const chainDigests = [frameDigest];
  const rawTurnFingerprints = [];
  let firstMsgDigest = "";

  for (let i = 0; i < turns.length; i++) {
    const turnStr = stableStringify(turns[i]);
    if (i === 0) {
      firstMsgDigest = sha256Hex(turnStr);
    }
    const prev = chainDigests[i];
    chainDigests.push(sha256Hex(`${prev}\0${turnStr}`));
    rawTurnFingerprints.push(computeRawTurnFingerprint(turns[i]));
  }

  return {
    protocol: proto,
    bareModel,
    hasTools,
    frameDigest,
    firstMsgDigest,
    chainDigests,
    rawTurnFingerprints,
    messageCount: turns.length,
    effortInfo,
  };
}

export function evaluatePrefixCompatibility(mainState, reqSnapshot) {
  if (!mainState || !reqSnapshot) {
    return { compatible: false, lcpMessages: 0, reason: "no_main_session" };
  }
  if (reqSnapshot.frameDigest !== mainState.frameDigest) {
    return { compatible: false, lcpMessages: 0, reason: "frame_mismatch" };
  }
  const maxCompare = Math.min(mainState.messageCount, reqSnapshot.messageCount);
  let lcpMessages = 0;
  for (let i = 0; i < maxCompare; i++) {
    if (mainState.chainDigests[i + 1] === reqSnapshot.chainDigests[i + 1]) {
      lcpMessages++;
    } else {
      break;
    }
  }
  if (lcpMessages === 0) {
    return { compatible: false, lcpMessages: 0, reason: "message_0_mismatch" };
  }
  const prefixLimit = Math.min(mainState.messageCount, Math.max(0, reqSnapshot.messageCount - 1));
  if (
    mainState.messageCount >= 2 &&
    lcpMessages < prefixLimit &&
    lcpMessages / mainState.messageCount < 0.5
  ) {
    return { compatible: false, lcpMessages, reason: "history_diverged" };
  }
  return { compatible: true, lcpMessages, reason: "lcp_matched" };
}

export function computePostRelayRequestDigest(protocol, bareTargetModel, snapshot) {
  const tail = snapshot?.chainDigests?.[snapshot.chainDigests.length - 1] ?? "";
  return sha256Hex(
    JSON.stringify([
      String(protocol || "").trim().toLowerCase(),
      stripModelPrefix(bareTargetModel),
      snapshot?.frameDigest ?? "",
      tail,
    ]),
  );
}

// ==================== B1: Extensible Auxiliary Request Classifier ====================

export function registerAuxAdapter(adapter) {
  if (!adapter || typeof adapter.classify !== "function") {
    throw new TypeError("aux adapter must provide a classify(ctx) function");
  }
  const name = typeof adapter.name === "string" && adapter.name.trim() ? adapter.name.trim() : `custom-${customAdapters.length + 1}`;
  const priority = typeof adapter.priority === "number" && Number.isFinite(adapter.priority) ? adapter.priority : 15;
  const entry = { name, priority, classify: adapter.classify };
  customAdapters.push(entry);
  return () => {
    const idx = customAdapters.indexOf(entry);
    if (idx >= 0) customAdapters.splice(idx, 1);
  };
}

export function clearCustomAuxAdapters() {
  customAdapters.length = 0;
}

function getHeaderLower(headers, key) {
  if (!headers) return "";
  if (typeof headers.get === "function") {
    return (headers.get(key) || "").trim();
  }
  if (isPlainObject(headers)) {
    const target = key.toLowerCase();
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === target && typeof v === "string") {
        return v.trim();
      }
    }
  }
  return "";
}

function countLineageMatches(mainState, reqSnapshot) {
  if (!mainState?.turnFingerprintSet || !reqSnapshot?.rawTurnFingerprints?.length) {
    return { nonFirstMatches: 0, totalMatches: 0 };
  }
  let nonFirstMatches = 0;
  let totalMatches = 0;
  for (let i = 0; i < reqSnapshot.rawTurnFingerprints.length; i++) {
    const fp = reqSnapshot.rawTurnFingerprints[i];
    if (mainState.turnFingerprintSet.has(fp)) {
      totalMatches++;
      if (i >= 1) nonFirstMatches++;
    }
  }
  return { nonFirstMatches, totalMatches };
}

// Note: Magpie GatewayContext (`internal/plugin/gateway.go`) does not forward client HTTP headers
// (`ctx.headers` is undefined in live `hooks.mjs`, and `hookKind()` only marks Claude Code / Codex
// subagents). Header lookups below serve unit/custom harnesses; live gateway traffic relies on
// `ctx.kind`, `body.metadata`, and `structural_heuristic` (`capped_downgrade` / `tool_stripped_branch`).
const BUILTIN_ADAPTERS = [
  {
    name: "subagent",
    priority: 10,
    classify(c) {
      const zcodeSource = getHeaderLower(c.headers, "x-zcode-query-source").toLowerCase();
      const zcodeSessType = getHeaderLower(c.headers, "x-zcode-session-type").toLowerCase();
      if (
        c.kind === "subagent" ||
        zcodeSource === "subagent" ||
        zcodeSessType === "subagent" ||
        Boolean(c.magpieSubagent)
      ) {
        return { role: "subagent", detector: "subagent", reason: "subagent_context" };
      }
      return null;
    },
  },
  {
    name: "explicit_purpose",
    priority: 20,
    classify(c) {
      const bodyPurpose =
        typeof c.body?.metadata?.purpose === "string"
          ? c.body.metadata.purpose.trim().toLowerCase()
          : "";
      const hdrPurpose = getHeaderLower(c.headers, "x-magpie-purpose").toLowerCase();
      const zcodeSource = getHeaderLower(c.headers, "x-zcode-query-source").toLowerCase();
      const purpose = bodyPurpose || hdrPurpose || zcodeSource;

      if (purpose && MAIN_PURPOSE_VALUES.has(purpose)) {
        return { role: "main", detector: "explicit_purpose", reason: `purpose:${purpose}` };
      }
      if (c.body?.metadata?.auxiliary === true || (purpose && AUX_PURPOSE_VALUES.has(purpose))) {
        return {
          role: "auxiliary",
          detector: "explicit_purpose",
          reason: purpose ? `purpose:${purpose}` : "metadata.auxiliary",
          purpose,
        };
      }
      return null;
    },
  },
  {
    name: "structural_heuristic",
    priority: 100,
    classify(c) {
      const { mainState, reqSnapshot, compat, bodyBytes, minBodyBytes, maxAuxOutputTokens } = c;
      if (!mainState || !reqSnapshot || reqSnapshot.messageCount < 2) {
        return null;
      }

      const { nonFirstMatches, totalMatches } = countLineageMatches(mainState, reqSnapshot);
      const hasLineage = (compat?.lcpMessages ?? 0) >= 1 || nonFirstMatches >= 1;
      if (!hasLineage) {
        return null;
      }

      if (bodyBytes < minBodyBytes) {
        return null;
      }

      const { effortInfo } = reqSnapshot;
      const reqMaxOutput = effortInfo.maxOutputTokens;
      const outputCapped =
        reqMaxOutput !== null &&
        reqMaxOutput <= maxAuxOutputTokens &&
        (mainState.maxOutputTokens == null || reqMaxOutput <= mainState.maxOutputTokens * 0.5);

      // Branch A: capped_downgrade
      const reqVirtualRank = effortInfo.disabled ? -1 : effortInfo.rank;
      if (
        outputCapped &&
        reqVirtualRank !== null &&
        mainState.effortRank !== null &&
        mainState.effortRank > reqVirtualRank
      ) {
        return {
          role: "auxiliary",
          detector: "capped_downgrade",
          reason: "effort_downgraded_and_output_capped",
        };
      }

      // Branch B: tool_stripped_branch
      const lineageHistoryCount = Math.max(compat?.lcpMessages ?? 0, totalMatches);
      if (
        mainState.hasTools === true &&
        reqSnapshot.hasTools === false &&
        lineageHistoryCount >= 2 &&
        reqMaxOutput !== null &&
        reqMaxOutput <= maxAuxOutputTokens
      ) {
        return {
          role: "auxiliary",
          detector: "tool_stripped_branch",
          reason: "tools_stripped_with_history_lineage",
        };
      }

      return null;
    },
  },
];

export function classifyRequestRole(params) {
  const chain = [...BUILTIN_ADAPTERS, ...customAdapters].sort((a, b) => a.priority - b.priority);
  for (const adapter of chain) {
    try {
      const res = adapter.classify(params);
      if (res && typeof res === "object" && (res.role === "main" || res.role === "auxiliary" || res.role === "subagent")) {
        return {
          role: res.role,
          detector: typeof res.detector === "string" && res.detector ? res.detector : adapter.name,
          reason: typeof res.reason === "string" ? res.reason : "",
          purpose: typeof res.purpose === "string" ? res.purpose : "",
        };
      }
    } catch {
      // fail-open across adapters
    }
  }
  return { role: "main", detector: "default", reason: "", purpose: "" };
}

// ==================== B4: Cross-Model Switch Validation ====================

function mimeToModality(mime) {
  const m = String(mime || "").trim().toLowerCase();
  if (!m) return null;
  if (m.startsWith("image/")) return "image";
  if (m.startsWith("video/")) return "video";
  if (m.startsWith("audio/")) return "audio";
  if (m === "application/pdf" || m.startsWith("application/pdf;")) return "pdf";
  return null;
}

export function scanBodyInputModalities(protocol, body) {
  const found = new Set();
  if (!isPlainObject(body)) return found;

  if (protocol === "gemini") {
    const contents = Array.isArray(body.contents) ? body.contents : [];
    for (const turn of contents) {
      const parts = Array.isArray(turn?.parts) ? turn.parts : [];
      for (const p of parts) {
        if (!isPlainObject(p)) continue;
        const inline = p.inlineData ?? p.inline_data;
        const fileData = p.fileData ?? p.file_data;
        const mod =
          mimeToModality(inline?.mimeType ?? inline?.mime_type) ??
          mimeToModality(fileData?.mimeType ?? fileData?.mime_type);
        if (mod) found.add(mod);
      }
    }
    return found;
  }

  if (protocol === "anthropic") {
    const scanNode = (node) => {
      if (!node) return;
      if (Array.isArray(node)) {
        for (const item of node) scanNode(item);
        return;
      }
      if (!isPlainObject(node)) return;
      if (node.type === "image") {
        found.add("image");
      } else if (node.type === "document") {
        found.add(mimeToModality(node.source?.media_type) ?? "pdf");
      } else if (node.type === "video") {
        found.add("video");
      } else if (node.type === "audio") {
        found.add("audio");
      } else if (node.type === "tool_result") {
        scanNode(node.content);
      } else if (node.source?.media_type) {
        const m = mimeToModality(node.source.media_type);
        if (m) found.add(m);
      }
    };
    const msgs = Array.isArray(body.messages) ? body.messages : [];
    for (const msg of msgs) {
      scanNode(msg?.content);
    }
    return found;
  }

  if (protocol === "chat") {
    const msgs = Array.isArray(body.messages) ? body.messages : [];
    for (const msg of msgs) {
      if (!Array.isArray(msg?.content)) continue;
      for (const part of msg.content) {
        if (!isPlainObject(part)) continue;
        if (part.type === "image_url" || part.type === "image") found.add("image");
        else if (part.type === "input_audio" || part.type === "audio") found.add("audio");
        else if (part.type === "video_url" || part.type === "video") found.add("video");
        else if (part.type === "file") {
          const mime = part.file?.mime_type ?? part.mime_type ?? "";
          const fname = String(part.file?.filename ?? part.filename ?? "").toLowerCase();
          const mod = mimeToModality(mime) ?? (fname.endsWith(".pdf") ? "pdf" : null);
          if (mod) found.add(mod);
        }
      }
    }
    return found;
  }

  if (protocol === "responses") {
    const scanInput = (node) => {
      if (!node) return;
      if (Array.isArray(node)) {
        for (const item of node) scanInput(item);
        return;
      }
      if (!isPlainObject(node)) return;
      if (node.type === "input_image" || node.type === "image") found.add("image");
      else if (node.type === "input_audio" || node.type === "audio") found.add("audio");
      else if (node.type === "input_video" || node.type === "video") found.add("video");
      else if (node.type === "input_file") {
        const mime = node.mime_type ?? "";
        const fname = String(node.filename ?? "").toLowerCase();
        const mod = mimeToModality(mime) ?? (fname.endsWith(".pdf") || !mime ? "pdf" : null);
        if (mod) found.add(mod);
      }
      if (node.content !== undefined) scanInput(node.content);
    };
    scanInput(body.input);
    return found;
  }

  return found;
}

function hasSealedThinkingBlocks(protocol, body) {
  if (!isPlainObject(body)) return false;
  if (protocol === "anthropic") {
    const msgs = Array.isArray(body.messages) ? body.messages : [];
    return msgs.some(
      (m) =>
        Array.isArray(m?.content) &&
        m.content.some((b) => isPlainObject(b) && b.type === "redacted_thinking"),
    );
  }
  if (protocol === "responses") {
    const items = Array.isArray(body.input) ? body.input : [];
    return items.some(
      (item) =>
        isPlainObject(item) &&
        item.type === "reasoning" &&
        typeof item.encrypted_content === "string" &&
        item.encrypted_content.trim().length > 0,
    );
  }
  return false;
}

function adaptTargetEffort(targetEntry, targetMeta, requestedEffort) {
  if (targetMeta?.isAliasFixed) {
    return "";
  }
  const levels = Array.isArray(targetMeta?.thinkingLevels) ? targetMeta.thinkingLevels : [];
  const supportsReasoning = Boolean(targetEntry?.capabilities?.reasoning) || levels.length > 0;
  if (!supportsReasoning) {
    return "none";
  }
  const want = normalizeEffort(requestedEffort);
  if (!want || want === "none") {
    return "";
  }
  if (levels.length === 0) {
    return want === "xhigh" ? "high" : want === "max" ? "high" : want;
  }
  if (levels.includes(want)) {
    return want;
  }
  if (want === "xhigh") {
    if (levels.includes("high")) return "high";
    return levels[levels.length - 1];
  }
  if (want === "max") {
    if (levels.includes("xhigh")) return "xhigh";
    if (levels.includes("high")) return "high";
    return levels[levels.length - 1];
  }
  if (want === "minimal") {
    if (levels.includes("low")) return "low";
    return levels[0];
  }
  if (want === "low") {
    return levels[0];
  }
  return levels.includes("medium") ? "medium" : levels[0];
}

export function validateCrossModelSwitch({
  body,
  bodyBytes,
  protocol,
  targetModelId,
  targetEffort = "low",
  authScope,
  nowMs = Date.now(),
} = {}) {
  const cleanTarget = stripModelPrefix(targetModelId);
  if (!cleanTarget) {
    return { ok: false, reason: "fallback_model_unconfigured", adaptedEffort: "" };
  }

  const scope = authScope !== undefined ? authScope : getRegisteredAuthScope({ nowMs });
  if (!scope) {
    return { ok: false, reason: "auth_scope_ambiguous", adaptedEffort: "" };
  }
  const models = getDiscoveredModels(scope) ?? getDiscoveredModels(scope, { foldEffortVariants: true });
  const targetEntry = models?.[cleanTarget] ?? null;
  if (!targetEntry) {
    return { ok: false, reason: "model_not_discovered", adaptedEffort: "" };
  }
  if (targetEntry.capabilities?.output?.text !== true) {
    return { ok: false, reason: "non_text_output_model", adaptedEffort: "" };
  }

  const metaMap = getModelMetadataMap(scope);
  const targetMeta = metaMap.get(cleanTarget) ?? null;

  // 2. Quota check (cached snapshot only, never blocks)
  const quotaWin = getCachedModelQuotaWindow(scope, cleanTarget, {
    discoveredModels: models,
    modelMetadataMap: metaMap,
    nowMs,
  });
  if (quotaWin && quotaWin.used === 100 && !quotaWin.aside) {
    return { ok: false, reason: "quota_exhausted", adaptedEffort: "" };
  }

  // 3. Context limit check:
  // In Antigravity2API (`catalog.go`), Google `input_token_limit` (`limit.context`) is a pure
  // input limit (do not deduct output reservation); Anthropic/OpenAI `limit.context` is a
  // combined input + output context window (deduct capped output reservation).
  const effortInfo = resolveRequestEffortAndMaxOutput(protocol, body, null);
  const bytes =
    typeof bodyBytes === "number" && Number.isFinite(bodyBytes)
      ? bodyBytes
      : Buffer.byteLength(JSON.stringify(body || {}), "utf8");
  const estInputTokens = Math.ceil(bytes / 3);
  const ctxLimit = Number(targetEntry.limit?.context || 0);
  const targetOutLimit = Number(targetEntry.limit?.output || 0);
  const targetSpec = resolveProtocolSpec(cleanTarget, targetMeta?.provider);
  const isPureInputLimit = targetSpec.npm === "@ai-sdk/google";
  if (
    !isPureInputLimit &&
    effortInfo.maxOutputTokens !== null &&
    targetOutLimit > 0 &&
    effortInfo.maxOutputTokens > targetOutLimit
  ) {
    return { ok: false, reason: "context_exceeded", adaptedEffort: "" };
  }
  if (ctxLimit > 0) {
    let reserveOutput = 0;
    if (!isPureInputLimit) {
      if (effortInfo.maxOutputTokens !== null) {
        reserveOutput = effortInfo.maxOutputTokens;
      } else if (targetSpec.npm === "@ai-sdk/anthropic" && targetOutLimit > 0) {
        reserveOutput = targetOutLimit;
      } else {
        reserveOutput = 4096;
      }
    }
    const protocolOverhead = Math.min(
      AUX_CONTEXT_PROTOCOL_OVERHEAD_TOKENS,
      Math.floor(ctxLimit * 0.1),
    );
    if (estInputTokens + protocolOverhead + reserveOutput > ctxLimit) {
      return { ok: false, reason: "context_exceeded", adaptedEffort: "" };
    }
  }

  // 4. Input modalities
  const usedModalities = scanBodyInputModalities(protocol, body);
  for (const mod of usedModalities) {
    if (targetEntry.capabilities?.input?.[mod] !== true) {
      return { ok: false, reason: `modality_unsupported:${mod}`, adaptedEffort: "" };
    }
  }

  // 5. Tools
  if (hasNonEmptyTools(protocol, body) && targetEntry.capabilities?.toolcall !== true) {
    return { ok: false, reason: "toolcall_unsupported", adaptedEffort: "" };
  }

  // 6. Sealed thinking compatibility in same-protocol passthrough
  const bareSource = stripModelPrefix(body?.model || "");
  if (bareSource !== cleanTarget && hasSealedThinkingBlocks(protocol, body)) {
    const sameAnthropic = protocol === "anthropic" && targetSpec.npm === "@ai-sdk/anthropic";
    const sameResponses = protocol === "responses" && targetSpec.npm === "@ai-sdk/openai-compatible";
    if (sameAnthropic || sameResponses) {
      return { ok: false, reason: "sealed_thinking_incompatible", adaptedEffort: "" };
    }
  }

  const adaptedEffort = adaptTargetEffort(targetEntry, targetMeta, targetEffort);
  return {
    ok: true,
    reason: "ok",
    targetModelId: cleanTarget,
    adaptedEffort,
  };
}

// ==================== State Stores: Main Session, Tickets, Diagnostics ====================

function makeSessionKey(originScope, sessionId, protocol = "any") {
  return `${originScope || "default"}\0${protocol || "any"}\0${sessionId}`;
}

function getFreshMainEntry(scopedKey, now, ttlMs) {
  const entry = mainSessionMap.get(scopedKey);
  if (!entry) return null;
  if (now - entry.updatedAt > ttlMs) {
    mainSessionMap.delete(scopedKey);
    return null;
  }
  mainSessionMap.delete(scopedKey);
  mainSessionMap.set(scopedKey, entry);
  return entry;
}

export function getMainSessionState(
  sessionId,
  origin = undefined,
  nowMs = Date.now(),
  ttlMs = DEFAULT_AUX_TTL_MS,
  protocol = undefined,
) {
  const sid = typeof sessionId === "string" ? sessionId.trim() : "";
  if (!sid) return null;
  const hasExplicitOrigin = typeof origin === "string" && origin.trim().length > 0;
  const org = hasExplicitOrigin ? origin.trim() : "default";
  const hasExplicitProto = typeof protocol === "string" && protocol.trim().length > 0;
  const proto = hasExplicitProto ? protocol.trim().toLowerCase() : "";

  if (hasExplicitProto) {
    const direct = getFreshMainEntry(makeSessionKey(org, sid, proto), nowMs, ttlMs);
    if (direct) return direct;
    if (hasExplicitOrigin && org !== "default") {
      return getFreshMainEntry(makeSessionKey("default", sid, proto), nowMs, ttlMs);
    }
    return null;
  }

  for (const [k, v] of [...mainSessionMap.entries()].reverse()) {
    if (v.sessionId === sid && (!hasExplicitOrigin || v.originScope === org || v.originScope === "default")) {
      const fresh = getFreshMainEntry(k, nowMs, ttlMs);
      if (fresh) return fresh;
    }
  }
  return null;
}

function saveMainSessionEntry(scopedKey, entry, now, ttlMs) {
  const existing = mainSessionMap.get(scopedKey);
  if (existing && existing.seq > entry.seq) {
    return;
  }
  if (existing) {
    mainSessionMap.delete(scopedKey);
  }
  if (mainSessionMap.size >= MAX_MAIN_SESSION_ENTRIES) {
    for (const [k, v] of mainSessionMap.entries()) {
      if (now - v.updatedAt > ttlMs) {
        mainSessionMap.delete(k);
      }
    }
    while (mainSessionMap.size >= MAX_MAIN_SESSION_ENTRIES) {
      const oldestKey = mainSessionMap.keys().next().value;
      if (oldestKey === undefined) break;
      mainSessionMap.delete(oldestKey);
    }
  }
  mainSessionMap.set(scopedKey, entry);
}

function commitMainSessionState({
  originScope = "default",
  sessionId,
  bareModel,
  snapshot,
  seq,
  nowMs = Date.now(),
  ttlMs = DEFAULT_AUX_TTL_MS,
  replyFingerprint = null,
}) {
  const sid = typeof sessionId === "string" ? sessionId.trim() : "";
  if (!sid || !snapshot) return;
  const scopedKey = makeSessionKey(originScope, sid, snapshot.protocol || "any");
  const existing = mainSessionMap.get(scopedKey);
  if (existing && existing.seq > seq) {
    return;
  }

  const turnSet = new Set(snapshot.rawTurnFingerprints);
  if (replyFingerprint) {
    turnSet.add(replyFingerprint);
  }

  // If seq === existing.seq (e.g. fetch committed then onResponse arrives with replyFingerprint), enrich turnSet
  if (existing && existing.seq === seq) {
    if (replyFingerprint) {
      existing.turnFingerprintSet.add(replyFingerprint);
    }
    existing.updatedAt = nowMs;
    return;
  }

  const headDigest = snapshot.chainDigests[snapshot.chainDigests.length - 1] ?? "";
  saveMainSessionEntry(
    scopedKey,
    {
      seq,
      originScope,
      sessionId: sid,
      bareModel: stripModelPrefix(bareModel || snapshot.bareModel),
      protocol: snapshot.protocol,
      hasTools: snapshot.hasTools,
      frameDigest: snapshot.frameDigest,
      chainDigests: snapshot.chainDigests,
      headDigest,
      messageCount: snapshot.messageCount,
      turnFingerprintSet: turnSet,
      effort: snapshot.effortInfo.effort,
      effortRank: snapshot.effortInfo.rank,
      maxOutputTokens: snapshot.effortInfo.maxOutputTokens,
      updatedAt: nowMs,
    },
    nowMs,
    ttlMs,
  );
}

function recordDiagnostic(entry) {
  auxDiagnostics.push(entry);
  while (auxDiagnostics.length > MAX_AUX_DIAGNOSTICS) {
    auxDiagnostics.shift();
  }
  return entry;
}

export function getAuxRoutingDiagnostics() {
  return auxDiagnostics.map((d) => ({ ...d }));
}

export function clearAuxRoutingDiagnostics() {
  auxDiagnostics.length = 0;
}

function pruneExpiredTickets(map, nowMs) {
  for (const [key, list] of map.entries()) {
    const kept = list.filter((t) => nowMs - t.createdAt <= AUX_TICKET_TTL_MS && !t.consumed);
    if (kept.length === 0) {
      map.delete(key);
    } else if (kept.length !== list.length) {
      map.set(key, kept);
    }
  }
}

function registerAuxIsolationTicket({
  sessionId,
  auxSessionId,
  bareTargetModel,
  postRelayRequestDigest,
  diagEntry,
  nowMs = Date.now(),
}) {
  pruneExpiredTickets(ticketsByDigest, nowMs);
  pruneExpiredTickets(ticketsByModel, nowMs);

  const ticket = {
    sessionId,
    auxSessionId,
    bareTargetModel: stripModelPrefix(bareTargetModel),
    postRelayRequestDigest,
    createdAt: nowMs,
    consumed: false,
    diagEntry,
  };

  const digestKey = `${sessionId}\0${postRelayRequestDigest}`;
  const dList = ticketsByDigest.get(digestKey) ?? [];
  dList.push(ticket);
  ticketsByDigest.set(digestKey, dList);

  const modelKey = `${sessionId}\0${ticket.bareTargetModel}`;
  const mList = ticketsByModel.get(modelKey) ?? [];
  mList.push(ticket);
  ticketsByModel.set(modelKey, mList);

  return ticket;
}

function takeFirstValidTicket(map, key, nowMs) {
  const list = map.get(key);
  if (!list || list.length === 0) return null;
  while (list.length > 0) {
    const candidate = list.shift();
    if (!candidate.consumed && nowMs - candidate.createdAt <= AUX_TICKET_TTL_MS) {
      candidate.consumed = true;
      if (list.length === 0) map.delete(key);
      return candidate;
    }
  }
  map.delete(key);
  return null;
}

export function consumeAuxIsolationTicket({
  candidateSessionIds = [],
  bareTargetModel = "",
  postRelayRequestDigest = "",
  nowMs = Date.now(),
} = {}) {
  const cleanModel = stripModelPrefix(bareTargetModel);
  const sessions = [...new Set(candidateSessionIds.map((s) => String(s || "").trim()).filter(Boolean))];
  for (const sid of sessions) {
    if (postRelayRequestDigest) {
      const t = takeFirstValidTicket(ticketsByDigest, `${sid}\0${postRelayRequestDigest}`, nowMs);
      if (t) return t;
    }
    if (cleanModel) {
      const t = takeFirstValidTicket(ticketsByModel, `${sid}\0${cleanModel}`, nowMs);
      if (t) return t;
    }
  }
  return null;
}

export function markTicketUpstreamExecuted(ticket, info = {}) {
  if (!ticket?.diagEntry) return;
  ticket.diagEntry.upstreamExecuted = true;
  if (typeof info.outcome === "string") {
    ticket.diagEntry.upstreamOutcome = info.outcome;
  }
}

function registerPendingMainContext({ sessionId, originScope, snapshot, seq, nowMs }) {
  const list = pendingMainMap.get(sessionId) ?? [];
  const headDigest = snapshot.chainDigests[snapshot.chainDigests.length - 1] ?? "";
  // Prune stale (>60s)
  const fresh = list.filter((p) => nowMs - p.createdAt <= AUX_TICKET_TTL_MS);
  fresh.push({ originScope, frameDigest: snapshot.frameDigest, headDigest, seq, createdAt: nowMs });
  pendingMainMap.set(sessionId, fresh);
}

export function commitMainSessionFromFetch({
  candidateSessionIds = [],
  bareModel,
  snapshot,
  headerEffort = null,
  defaultThinkingLevel = null,
  nowMs = Date.now(),
  ttlMs = DEFAULT_AUX_TTL_MS,
}) {
  if (!snapshot) return;
  const sessions = [...new Set(candidateSessionIds.map((s) => String(s || "").trim()).filter(Boolean))];
  if (sessions.length === 0) return;

  const headDigest = snapshot.chainDigests[snapshot.chainDigests.length - 1] ?? "";
  let originScope = "default";
  let matchedSid = sessions[0];
  let seq = ++nextMainSeq;

  for (const sid of sessions) {
    const list = pendingMainMap.get(sid);
    if (!list || list.length === 0) continue;
    const idx = list.findIndex(
      (p) => p.frameDigest === snapshot.frameDigest && p.headDigest === headDigest,
    );
    if (idx >= 0) {
      const item = list[idx];
      list.splice(idx, 1);
      if (list.length === 0) pendingMainMap.delete(sid);
      originScope = item.originScope;
      matchedSid = sid;
      seq = item.seq;
      break;
    }
  }

  // Enrich effort if null and defaultThinkingLevel is known
  const enrichedSnapshot = {
    ...snapshot,
    effortInfo: { ...snapshot.effortInfo },
  };
  if (
    !enrichedSnapshot.effortInfo.disabled &&
    enrichedSnapshot.effortInfo.effort === null &&
    typeof defaultThinkingLevel === "string"
  ) {
    const norm = normalizeEffort(defaultThinkingLevel);
    if (norm && norm !== "none") {
      enrichedSnapshot.effortInfo.effort = norm;
      enrichedSnapshot.effortInfo.rank = EFFORT_RANK[norm];
    }
  }
  if (headerEffort && !enrichedSnapshot.effortInfo.disabled && enrichedSnapshot.effortInfo.effort === null) {
    const norm = normalizeEffort(headerEffort);
    if (norm && norm !== "none") {
      enrichedSnapshot.effortInfo.effort = norm;
      enrichedSnapshot.effortInfo.rank = EFFORT_RANK[norm];
    }
  }

  commitMainSessionState({
    originScope,
    sessionId: matchedSid,
    bareModel,
    snapshot: enrichedSnapshot,
    seq,
    nowMs,
    ttlMs,
  });
}

export function clearAuxRouterState() {
  mainSessionMap.clear();
  pendingMainMap.clear();
  ticketsByDigest.clear();
  ticketsByModel.clear();
  auxDiagnostics.length = 0;
  nextMainSeq = 0;
  auxRouterGeneration++;
  runtimeContext = {
    directory: "",
    magpie: null,
    staticOptions: null,
    authScope: null,
    authScopeAmbiguous: false,
    defaultBaseUrl: DEFAULT_BASE_URL,
  };
  pluginsJsonCache = { path: "", checkedAtMs: 0, mtimeMs: -1, size: -1, options: null };
  pluginAuthCache = {
    dir: "",
    defaultBaseUrl: DEFAULT_BASE_URL,
    stamp: "",
    status: "none",
    scope: null,
  };
  settingsUiCache = {
    path: "",
    mtimeMs: -1,
    size: -1,
    exists: false,
    chosenOpts: null,
  };
}

// ==================== Gateway Hook Handlers ====================

function resolveSessionIdForGateway(ctx, body) {
  if (typeof ctx?.session === "string" && ctx.session.trim()) {
    return ctx.session.trim();
  }
  return "";
}

function isSameModelFamily(modelA, modelB) {
  const cleanA = stripModelPrefix(modelA);
  const cleanB = stripModelPrefix(modelB);
  if (!cleanA || !cleanB) return false;
  if (cleanA === cleanB) return true;
  return foldModelId(cleanA).baseId === foldModelId(cleanB).baseId;
}

function stripModelFromPath(protocol, reqPath) {
  if (protocol !== "gemini" || typeof reqPath !== "string") return "";
  const m =
    reqPath.match(/\/models\/([^/:?#]+):(?:generateContent|streamGenerateContent|countTokens)$/i) ||
    reqPath.match(/\/models\/([^/:?#]+)/i);
  if (!m) return "";
  try {
    return stripModelPrefix(decodeURIComponent(m[1]));
  } catch {
    return stripModelPrefix(m[1]);
  }
}

export async function handleGatewayOnRequest(body, ctx = {}) {
  const nowFn = typeof ctx.nowFn === "function" ? ctx.nowFn : Date.now;
  const nowMs = nowFn();

  if (!isPlainObject(body)) return undefined;

  const hadForgedRelay = RELAY_FIELD in body;
  const cleanInputBody = hadForgedRelay ? (() => { const c = { ...body }; delete c[RELAY_FIELD]; return c; })() : body;

  const reqPath = typeof ctx.path === "string" ? ctx.path : "";
  const sessionId = resolveSessionIdForGateway(ctx, cleanInputBody);
  if (reqPath.startsWith("/backend-api/") || !sessionId) {
    return hadForgedRelay ? cleanInputBody : undefined;
  }

  const live = await readLiveAuxOptions(ctx.options, { nowFn });
  if (live.preserveCacheEffort === false) {
    return hadForgedRelay ? cleanInputBody : undefined;
  }

  const protocol = typeof ctx.protocol === "string" ? ctx.protocol.trim().toLowerCase() : "";
  if (!protocol || !["chat", "responses", "anthropic", "gemini"].includes(protocol)) {
    return hadForgedRelay ? cleanInputBody : undefined;
  }

  const rawReqModel = cleanInputBody.model || ctx.model || "";
  if (isExplicitForeignProviderModel(rawReqModel)) {
    return hadForgedRelay ? cleanInputBody : undefined;
  }

  const originScope = typeof ctx.origin === "string" && ctx.origin.trim() ? ctx.origin.trim() : "default";
  const reqBodyStr = JSON.stringify(cleanInputBody);
  const bodyBytes = Buffer.byteLength(reqBodyStr, "utf8");
  const reqSnapshot = extractConversationSnapshot(protocol, cleanInputBody, null);
  const bareReqModel =
    stripModelPrefix(rawReqModel) || stripModelFromPath(protocol, reqPath);
  const mainState = getMainSessionState(sessionId, originScope, nowMs, live.ttlMs, protocol);
  const authScope =
    ctx.authScope !== undefined ? ctx.authScope : getRegisteredAuthScope({ nowMs });
  const compat = mainState ? evaluatePrefixCompatibility(mainState, reqSnapshot) : null;

  const classification = classifyRequestRole({
    body: cleanInputBody,
    bodyBytes,
    protocol,
    kind: ctx.kind || "",
    headers: ctx.headers || null,
    magpieSubagent: ctx.magpieSubagent || "",
    mainState,
    reqSnapshot,
    compat,
    minBodyBytes: live.minBodyBytes,
    maxAuxOutputTokens: live.maxAuxOutputTokens,
  });

  if (classification.role === "subagent") {
    return hadForgedRelay ? cleanInputBody : undefined;
  }

  if (classification.role === "main") {
    if (authScope && isCatalogKnownNonAgyModel(authScope, rawReqModel, bareReqModel)) {
      return hadForgedRelay ? cleanInputBody : undefined;
    }
    const seq = ++nextMainSeq;
    const meta = authScope ? (getModelMetadataMap(authScope).get(bareReqModel) ?? null) : null;
    const enrichedSnapshot = {
      ...reqSnapshot,
      effortInfo: { ...reqSnapshot.effortInfo },
    };
    if (
      !enrichedSnapshot.effortInfo.disabled &&
      enrichedSnapshot.effortInfo.effort === null &&
      typeof meta?.defaultThinkingLevel === "string"
    ) {
      const defEff = normalizeEffort(meta.defaultThinkingLevel);
      if (defEff && defEff !== "none") {
        enrichedSnapshot.effortInfo.effort = defEff;
        enrichedSnapshot.effortInfo.rank = EFFORT_RANK[defEff];
      }
    }

    if (ctx.state && typeof ctx.state === "object") {
      ctx.state._agy2apiMainCandidate = {
        seq,
        originScope,
        sessionId,
        bareModel: bareReqModel,
        snapshot: enrichedSnapshot,
        ttlMs: live.ttlMs,
        generation: auxRouterGeneration,
      };
    }
    registerPendingMainContext({
      sessionId,
      originScope,
      snapshot: enrichedSnapshot,
      seq,
      nowMs,
    });
    return hadForgedRelay ? cleanInputBody : undefined;
  }

  // role === "auxiliary"
  const originalEffort = reqSnapshot.effortInfo.disabled
    ? "disabled"
    : (reqSnapshot.effortInfo.effort ?? "");
  const sessionHash = sha256Hex(sessionId).slice(0, 12);

  // Branch 2: Compatible with main session warm prefix
  if (compat && compat.compatible === true && mainState) {
    let routedModel = bareReqModel;
    let routedEffort = originalEffort;
    let fallbackRejectedReason = "";
    let outBody = hadForgedRelay ? cleanInputBody : undefined;

    if (bareReqModel && mainState.bareModel && !isSameModelFamily(bareReqModel, mainState.bareModel)) {
      if (!authScope) {
        fallbackRejectedReason = "auth_scope_ambiguous";
      } else if (bodyBytes <= MAX_RELAY_BODY_BYTES) {
        const secret = ensureRelaySecret({
          relaySecret: live.relaySecret || ctx.options?.relaySecret,
        });
        if (!secret) {
          fallbackRejectedReason = "relay_secret_unavailable";
        } else {
          if (!getDiscoveredModels(authScope)) {
            await ensureModelsDiscovered(authScope, undefined, {
              signal: ctx.signal,
              timeoutMs: 3000,
              fetchImpl: ctx.fetchImpl,
            }).catch(() => null);
          }
          const validation = validateCrossModelSwitch({
            body: cleanInputBody,
            bodyBytes,
            protocol,
            targetModelId: mainState.bareModel,
            targetEffort: mainState.effort || "",
            authScope,
            nowMs,
          });
          if (!validation.ok) {
            fallbackRejectedReason = validation.reason;
          } else {
            const relayPayload = signRelayPayload(secret, {
              toModel: `agy2api/${validation.targetModelId}`,
              toEffort: validation.adaptedEffort,
              proto: protocol,
              ts: nowMs,
              nonce: crypto.randomBytes(12).toString("hex"),
            });
            if (relayPayload) {
              outBody = { ...cleanInputBody, [RELAY_FIELD]: relayPayload };
              routedModel = validation.targetModelId;
              routedEffort = validation.adaptedEffort || originalEffort;
            }
          }
        }
      } else {
        fallbackRejectedReason = "payload_too_large";
      }
    } else if (mainState.effort && !reqSnapshot.effortInfo.disabled) {
      routedEffort = mainState.effort;
    }

    recordDiagnostic({
      timestamp: new Date(nowMs).toISOString(),
      sessionHash,
      protocol,
      detector: classification.detector,
      compatible: true,
      lcpMessages: compat.lcpMessages,
      reason: compat.reason,
      policy: "preserve_cache",
      originalModel: bareReqModel,
      originalEffort,
      routedModel,
      routedEffort,
      sessionIsolated: false,
      fallbackRejectedReason,
    });

    return outBody;
  }

  // Branch 3: Incompatible with main session (or no main session) -> active session isolation + policy
  const compatReason = compat ? compat.reason : "no_main_session";
  const lcpMessages = compat ? compat.lcpMessages : 0;
  const auxSessionId =
    "agy2api-aux-v1-" +
    sha256Hex(
      JSON.stringify([sessionId, reqSnapshot.frameDigest, reqSnapshot.firstMsgDigest]),
    ).slice(0, 32);

  let effectivePolicy = live.auxIncompatiblePolicy;
  let routedModel = bareReqModel;
  let routedEffort = originalEffort;
  let fallbackRejectedReason = "";
  let outBody = hadForgedRelay ? cleanInputBody : undefined;

  if (effectivePolicy === "fallback_model") {
    const cleanFallback = stripModelPrefix(live.auxFallbackModel);
    if (!cleanFallback) {
      fallbackRejectedReason = "fallback_model_unconfigured";
      effectivePolicy = "current_low";
    } else if (!authScope) {
      fallbackRejectedReason = "auth_scope_ambiguous";
      effectivePolicy = "current_low";
    } else if (bodyBytes > MAX_RELAY_BODY_BYTES) {
      fallbackRejectedReason = "payload_too_large";
      effectivePolicy = "current_low";
    } else {
      const secret = ensureRelaySecret({
        relaySecret: live.relaySecret || ctx.options?.relaySecret,
      });
      if (!secret) {
        fallbackRejectedReason = "relay_secret_unavailable";
        effectivePolicy = "current_low";
      } else {
        if (!getDiscoveredModels(authScope)) {
          await ensureModelsDiscovered(authScope, undefined, {
            signal: ctx.signal,
            timeoutMs: 3000,
            fetchImpl: ctx.fetchImpl,
          }).catch(() => null);
        }
        const validation = validateCrossModelSwitch({
          body: cleanInputBody,
          bodyBytes,
          protocol,
          targetModelId: cleanFallback,
          targetEffort: live.auxFallbackEffort || "low",
          authScope,
          nowMs,
        });
        if (!validation.ok) {
          fallbackRejectedReason = validation.reason;
          effectivePolicy = "current_low";
        } else {
          const relayPayload = signRelayPayload(secret, {
            toModel: `agy2api/${validation.targetModelId}`,
            toEffort: validation.adaptedEffort,
            proto: protocol,
            ts: nowMs,
            nonce: crypto.randomBytes(12).toString("hex"),
          });
          if (relayPayload) {
            outBody = { ...cleanInputBody, [RELAY_FIELD]: relayPayload };
            routedModel = validation.targetModelId;
            routedEffort = validation.adaptedEffort || originalEffort;
          } else {
            fallbackRejectedReason = "relay_sign_failed";
            effectivePolicy = "current_low";
          }
        }
      }
    }
  }

  if (effectivePolicy === "current_low") {
    const alreadyLowOrDisabled =
      reqSnapshot.effortInfo.disabled ||
      reqSnapshot.effortInfo.effort === "low" ||
      reqSnapshot.effortInfo.effort === "minimal";
    if (!alreadyLowOrDisabled) {
      outBody = applyEffortToBody(protocol, cleanInputBody, "low");
      routedEffort = "low";
    }
  }

  const diagEntry = recordDiagnostic({
    timestamp: new Date(nowMs).toISOString(),
    sessionHash,
    protocol,
    detector: classification.detector,
    compatible: false,
    lcpMessages,
    reason: compatReason,
    policy: effectivePolicy,
    originalModel: bareReqModel,
    originalEffort,
    routedModel,
    routedEffort,
    sessionIsolated: true,
    fallbackRejectedReason,
  });

  const postRelayRequestDigest = computePostRelayRequestDigest(
    protocol,
    routedModel || bareReqModel,
    reqSnapshot,
  );
  registerAuxIsolationTicket({
    sessionId,
    auxSessionId,
    bareTargetModel: routedModel || bareReqModel,
    postRelayRequestDigest,
    diagEntry,
    nowMs,
  });

  return outBody;
}

export async function handleGatewayOnResponse(reply, ctx = {}) {
  if (ctx?.success !== true) return;
  const candidate = ctx?.state?._agy2apiMainCandidate;
  if (!candidate || candidate.generation !== auxRouterGeneration) return;

  const nowFn = typeof ctx.nowFn === "function" ? ctx.nowFn : Date.now;
  const nowMs = nowFn();
  const replyFp = extractAssistantReplyFingerprint(candidate.snapshot?.protocol, reply);

  commitMainSessionState({
    originScope: candidate.originScope,
    sessionId: candidate.sessionId,
    bareModel: candidate.bareModel,
    snapshot: candidate.snapshot,
    seq: candidate.seq,
    nowMs,
    ttlMs: candidate.ttlMs,
    replyFingerprint: replyFp,
  });
}
