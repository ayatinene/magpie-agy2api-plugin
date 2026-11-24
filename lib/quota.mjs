import {
  adminFetch,
  buildAuthScopeKey,
  clearAdminSettingsCache,
  fetchAdminSettingsCached,
  normalizeBaseUrl,
  resolveAllowedAccountsForApiKey,
} from "./auth.mjs";
import {
  foldModelId,
  getDiscoveredModels,
  getModelMetadataMap,
  getModelQuotaGroupMap,
  titleCaseModelId,
} from "./models.mjs";

const clampPct = (n) => Math.max(0, Math.min(100, Math.round(n)));

function minOf(arr) {
  let m = arr[0];
  for (let i = 1; i < arr.length; i++) {
    if (arr[i] < m) m = arr[i];
  }
  return m;
}

function maxOf(arr) {
  let m = arr[0];
  for (let i = 1; i < arr.length; i++) {
    if (arr[i] > m) m = arr[i];
  }
  return m;
}

function computeUsedFromRemPct(rawRemPct) {
  if (rawRemPct === null || rawRemPct === undefined || !Number.isFinite(rawRemPct)) {
    return null;
  }
  if (rawRemPct <= 0) return 100;
  if (rawRemPct >= 100) return 0;
  return Math.min(99, Math.max(0, Math.round(100 - rawRemPct)));
}

function safeToISOString(ms) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return undefined;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return undefined;
  try {
    return d.toISOString();
  } catch {
    return undefined;
  }
}

const ACCOUNT_MODELS_CACHE_TTL_MS = 60_000;
const ACCOUNT_MODELS_CONCURRENCY = 6;

const quotaCache = new Map();
const inFlightFetches = new Map();
const lastRefreshAt = new Map();
const lastRefreshState = new Map();
const accountModelsCache = new Map();
const inFlightAccountModels = new Map();

export function clearQuotaCache() {
  quotaCache.clear();
  inFlightFetches.clear();
  lastRefreshAt.clear();
  lastRefreshState.clear();
  accountModelsCache.clear();
  inFlightAccountModels.clear();
  clearAdminSettingsCache();
}

export function isSchedulableAccount(account) {
  if (!account || typeof account !== "object") return false;
  const state = String(account.state || "").trim().toLowerCase();
  return state === "ready" || state === "cooling";
}

export function getTierInfo(account) {
  const raw = String(
    account?.tier || account?.subscription_tier || account?.quota?.subscription_tier || "",
  )
    .trim()
    .toLowerCase();
  if (raw.includes("ultra") || raw.includes("helium")) {
    return { tier: "ULTRA", weight: 2.0 };
  }
  if (raw.includes("pro") || raw.includes("premium") || raw.includes("advanced")) {
    return { tier: "PRO", weight: 1.5 };
  }
  return { tier: "FREE", weight: 1.0 };
}

// Antigravity2API reports two different things, kept apart here:
// - a quota pool is what an account actually owns: the prefix of the bucket ids in its
//   `/api/accounts` `quota` (gemini-5h and gemini-weekly are the "gemini" pool). Summary
//   windows and per-account details are built from pools only.
// - a quota group is the `quota_group` `/api/models` gives a model. It only says which pool
//   the model is billed to, and each account resolves it to one of its own pools
//   (`resolveAccountPool`). Per-model routing windows are built from groups.

// Pool a bucket belongs to: its id without the window suffix.
export function stripBucketGroup(bucketId, windowHint = "") {
  const raw = String(bucketId || "").trim().toLowerCase();
  if (!raw) return "";
  const stripped = raw.replace(/-(?:5h|weekly)$/i, "");
  if (stripped !== raw) return stripped;
  const win = String(windowHint || "").trim().toLowerCase();
  if (win && raw.endsWith(`-${win}`)) {
    return raw.slice(0, -(win.length + 1));
  }
  return raw;
}

export function getPoolDisplayMeta(poolKey) {
  const key = String(poolKey || "").trim().toLowerCase();
  if (key === "gemini") {
    return { key, displayName: "Gemini", shortLabel: "Gemini", rank: 0 };
  }
  if (key === "3p") {
    return { key, displayName: "Claude & GPT", shortLabel: "Claude", rank: 1 };
  }
  if (key === "gemini-argon-wtu") {
    return { key, displayName: "Gemini 4 Argon", shortLabel: "Argon", rank: 2 };
  }
  const friendly = titleCaseModelId(key || "Default");
  return { key, displayName: friendly, shortLabel: friendly, rank: 10 };
}

function parseTimestampMs(raw) {
  if (raw === undefined || raw === null || raw === "") return null;
  let ms;
  if (typeof raw === "number") {
    if (!Number.isFinite(raw)) return null;
    ms = raw < 1e11 ? raw * 1000 : raw;
  } else {
    ms = Date.parse(String(raw));
  }
  if (!Number.isFinite(ms)) return null;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return null;
  try {
    d.toISOString();
    return ms;
  } catch {
    return null;
  }
}

function parseFutureMs(raw, nowMs) {
  const ms = parseTimestampMs(raw);
  if (ms === null || ms <= nowMs) return null;
  return ms;
}

function extractFraction(bucket) {
  if (!bucket || typeof bucket !== "object") return null;
  if (bucket.remaining_fraction !== undefined) {
    const v = bucket.remaining_fraction;
    return typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1 ? v : null;
  }
  if (bucket.remaining_percentage !== undefined) {
    const v = bucket.remaining_percentage;
    return typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 100 ? v / 100 : null;
  }
  if (bucket.percentage !== undefined) {
    const v = bucket.percentage;
    return typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 100 ? v / 100 : null;
  }
  if (bucket.remaining !== undefined) {
    const v = bucket.remaining;
    return typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1 ? v : null;
  }
  return null;
}

function hasUsableAiCredits(account) {
  if (account?.ai_credits !== true) return false;
  if (account.credit_balance !== undefined && account.credit_balance !== null) {
    const bal = Number(account.credit_balance);
    if (!Number.isFinite(bal) || bal <= 0) return false;
    if (account.credit_minimum !== undefined && account.credit_minimum !== null) {
      const min = Number(account.credit_minimum);
      if (!Number.isFinite(min) || min < 0 || bal < min) return false;
    }
  }
  return true;
}

function inferModelFamily(baseId) {
  const lower = String(baseId || "").toLowerCase();
  if (lower.startsWith("claude")) return "Claude";
  if (lower.startsWith("gemini") || lower.startsWith("imagen")) return "Gemini";
  if (lower.startsWith("gpt")) return "GPT";
  return titleCaseModelId(lower.split("-")[0] || "Model");
}

function collectModelInfos(discoveredModels, foldEffortVariants = false, modelMetadataMap = null) {
  const infos = [];
  const seen = new Set();
  const lookupMeta = (id) => {
    if (!modelMetadataMap) return null;
    if (modelMetadataMap instanceof Map) return modelMetadataMap.get(id) ?? null;
    if (typeof modelMetadataMap === "object") return modelMetadataMap[id] ?? null;
    return null;
  };

  if (discoveredModels && typeof discoveredModels === "object") {
    const entries = Array.isArray(discoveredModels)
      ? discoveredModels.map((m) => [m?.id, m])
      : Object.entries(discoveredModels);
    for (const [id, m] of entries) {
      if (!id || !m || typeof m !== "object") continue;
      const cleanId = String(id).trim().replace(/^models\//, "");
      if (!cleanId) continue;
      if (foldEffortVariants && lookupMeta(cleanId)?.isSynthetic) continue;
      if (seen.has(cleanId)) continue;
      seen.add(cleanId);
      infos.push({
        id: cleanId,
        name:
          typeof m.name === "string" && m.name.trim()
            ? m.name.trim()
            : titleCaseModelId(cleanId),
        family:
          typeof m.family === "string" && m.family.trim()
            ? m.family.trim()
            : inferModelFamily(cleanId),
      });
    }
  }

  return infos;
}

function accountPoolKeys(account) {
  const keys = new Set();
  const quotaArr = Array.isArray(account?.quota) ? account.quota : [];
  for (const b of quotaArr) {
    if (!b || typeof b !== "object") continue;
    const key = stripBucketGroup(b.bucket_id, b.window);
    if (key) keys.add(key);
  }
  return keys;
}

// The pools that exist are the ones schedulable accounts report buckets for. A model's
// quota group is not one of them unless some account really has buckets under that name.
function discoverQuotaPools(schedulable) {
  const poolsMap = new Map();
  let seq = 0;
  for (const acc of schedulable) {
    for (const key of accountPoolKeys(acc)) {
      if (!poolsMap.has(key)) {
        poolsMap.set(key, { ...getPoolDisplayMeta(key), order: seq++ });
      }
    }
  }
  return [...poolsMap.values()].sort((a, b) => {
    if (a.rank !== b.rank) return a.rank - b.rank;
    return a.order - b.order;
  });
}

// Same rule as `entry.group` in Antigravity2API's balancer: an account without buckets for
// a group bills it to this pool when it has that one. Today only Argon has such a rule: it
// has its own weekly bucket on some accounts and is drawn from the Gemini pool on the rest.
const GROUP_FALLBACK_POOL = { "gemini-argon-wtu": "gemini" };

// The pool this account bills a model quota group to, decided by the buckets it reports.
export function resolveAccountPool(account, groupKey) {
  const key = String(groupKey || "").trim().toLowerCase();
  const fallback = GROUP_FALLBACK_POOL[key];
  if (!fallback) return key;
  const owned = accountPoolKeys(account);
  return !owned.has(key) && owned.has(fallback) ? fallback : key;
}

// What the account has left in one of its own pools, and that pool's cooldown.
export function extractAccountPoolQuota(account, poolKey, nowMs = Date.now(), reservePct = 0) {
  const key = String(poolKey || "").trim().toLowerCase();
  const quotaArr = Array.isArray(account?.quota) ? account.quota : [];
  const cooldownMap =
    account?.cooldown && typeof account.cooldown === "object" ? account.cooldown : {};

  const cooldownMs = parseFutureMs(cooldownMap[key], nowMs);

  let h5 = null;
  let weekly = null;
  let weeklyFraction = null;
  let reset5hMs = null;
  let reset7dMs = null;
  let weeklyResetRawMs = null;
  let foundBucket = false;

  for (const b of quotaArr) {
    if (!b || typeof b !== "object") continue;
    if (stripBucketGroup(b.bucket_id, b.window) !== key) continue;

    foundBucket = true;
    const rawResetMs = parseTimestampMs(b.reset_time ?? b.resets_at ?? b.reset_at);
    const isRenewed = rawResetMs !== null && rawResetMs <= nowMs;
    const frac = isRenewed ? 1 : extractFraction(b);
    const pct = frac !== null ? frac * 100 : null;
    const futureResetMs = !isRenewed && rawResetMs !== null && rawResetMs > nowMs ? rawResetMs : null;

    const win = String(b.window || "").trim().toLowerCase();
    const bid = String(b.bucket_id || "").trim().toLowerCase();

    if (win === "weekly" || win === "7d" || /-weekly$/i.test(bid)) {
      if (pct !== null && (weekly === null || pct < weekly)) {
        weekly = pct;
      }
      if (frac !== null && (weeklyFraction === null || frac < weeklyFraction)) {
        weeklyFraction = frac;
        weeklyResetRawMs = isRenewed ? null : rawResetMs;
      } else if (weeklyResetRawMs === null && !isRenewed && rawResetMs !== null) {
        weeklyResetRawMs = rawResetMs;
      }
      if (futureResetMs !== null && (reset7dMs === null || futureResetMs < reset7dMs)) {
        reset7dMs = futureResetMs;
      }
    } else if (win === "5h" || /-5h$/i.test(bid)) {
      if (pct !== null && (h5 === null || pct < h5)) {
        h5 = pct;
      }
      if (futureResetMs !== null && (reset5hMs === null || futureResetMs < reset5hMs)) {
        reset5hMs = futureResetMs;
      }
    } else if (pct !== null) {
      if (futureResetMs !== null && futureResetMs - nowMs > 12 * 3600 * 1000) {
        if (weekly === null || pct < weekly) weekly = pct;
        if (frac !== null && (weeklyFraction === null || frac < weeklyFraction)) {
          weeklyFraction = frac;
          weeklyResetRawMs = rawResetMs;
        }
        if (futureResetMs !== null && (reset7dMs === null || futureResetMs < reset7dMs)) {
          reset7dMs = futureResetMs;
        }
      } else {
        if (h5 === null || pct < h5) h5 = pct;
        if (futureResetMs !== null && (reset5hMs === null || futureResetMs < reset5hMs)) {
          reset5hMs = futureResetMs;
        }
      }
    }
  }

  const hasQuotaSnapshot = Boolean(account?.quota_at) || quotaArr.length > 0;
  const known = (hasQuotaSnapshot && foundBucket && (h5 !== null || weekly !== null)) || cooldownMs !== null;

  if (!known) {
    return {
      known: false,
      inCooldown: false,
      cooldownMs: null,
      h5: null,
      weekly: null,
      weeklyFraction: null,
      weeklyResetRawMs: null,
      reset5hMs: null,
      reset7dMs: null,
      bucketRem: null,
      bucketResetMs: null,
      effectiveRem: null,
      resetEffectiveMs: null,
    };
  }

  const h5Exhausted = h5 !== null && h5 <= reservePct;
  const weeklyExhausted = weekly !== null && weekly <= reservePct;

  let bucketRem;
  if (weeklyExhausted || h5Exhausted) {
    bucketRem = 0;
  } else if (weekly !== null && h5 !== null) {
    bucketRem = Math.min(h5, weekly);
  } else {
    bucketRem = h5 ?? weekly;
  }

  let bucketResetMs;
  if (weeklyExhausted && h5Exhausted) {
    bucketResetMs =
      reset7dMs !== null && reset5hMs !== null ? Math.max(reset7dMs, reset5hMs) : null;
  } else if (weeklyExhausted) {
    bucketResetMs = reset7dMs;
  } else if (h5Exhausted) {
    bucketResetMs = reset5hMs;
  } else {
    bucketResetMs = reset5hMs ?? reset7dMs;
  }

  const effectiveRem = cooldownMs !== null ? 0 : bucketRem;

  let resetEffectiveMs;
  if (cooldownMs !== null) {
    resetEffectiveMs =
      bucketResetMs === null || bucketResetMs < cooldownMs ? cooldownMs : bucketResetMs;
  } else {
    resetEffectiveMs = bucketResetMs;
  }

  return {
    known: true,
    inCooldown: cooldownMs !== null,
    cooldownMs,
    h5,
    weekly,
    weeklyFraction,
    weeklyResetRawMs,
    reset5hMs,
    reset7dMs,
    bucketRem,
    bucketResetMs,
    effectiveRem,
    resetEffectiveMs,
  };
}

// What the account has left for a model quota group: the quota of the pool it bills that
// group to.
export function extractAccountGroupQuota(account, groupKey, nowMs = Date.now(), reservePct = 0) {
  const pool = resolveAccountPool(account, groupKey);
  return { pool, ...extractAccountPoolQuota(account, pool, nowMs, reservePct) };
}

class UnionFind {
  constructor(n) {
    this.parent = Array.from({ length: n }, (_, i) => i);
  }
  find(x) {
    while (this.parent[x] !== x) {
      this.parent[x] = this.parent[this.parent[x]];
      x = this.parent[x];
    }
    return x;
  }
  union(a, b) {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent[rb] = ra;
  }
}

// Aggregates what the accounts have left, each in the pool `poolOf(account)` names.
// Accounts are deduplicated only with peers drawing from the same pool: `shared` lists
// them per pool, and family members share the weekly bucket of that pool.
// With a constant `poolOf` this is one actual pool; with `resolveAccountPool` it is a model
// quota group, where accounts may be drawing from different pools.
function computePoolAggregate(schedulable, poolOf, nowMs, accountTags, reservePct = 0) {
  const n = schedulable.length;
  if (n === 0) {
    return {
      componentCount: 0,
      pools: [],
      usedEffective: null,
      used5h: null,
      used7d: null,
      resetsAtEffective: undefined,
      resetsAt5h: undefined,
      resetsAt7d: undefined,
      span: 604800,
    };
  }

  const idToIndex = new Map();
  const pools = new Array(n);
  const quotas = new Array(n);
  for (let i = 0; i < n; i++) {
    const acc = schedulable[i];
    const id = String(acc?.id || "").trim().toLowerCase();
    if (id) idToIndex.set(id, i);
    pools[i] = poolOf(acc);
    quotas[i] = extractAccountPoolQuota(acc, pools[i], nowMs, reservePct);
  }

  const uf = new UnionFind(n);

  for (let i = 0; i < n; i++) {
    const acc = schedulable[i];
    const q = quotas[i];

    // 1. Explicit shared links for the pool this account draws from
    if (Array.isArray(acc?.shared?.[pools[i]])) {
      for (const peerRaw of acc.shared[pools[i]]) {
        const peerId = String(peerRaw || "").trim().toLowerCase();
        const j = idToIndex.get(peerId);
        if (j !== undefined && j !== i && pools[j] === pools[i]) {
          uf.union(i, j);
          accountTags[i].shared = true;
          accountTags[j].shared = true;
        }
      }
    }

    // 2. Family links: union if both have started weekly bucket (< 1) with reset_time within 2s
    if (Array.isArray(acc?.family)) {
      for (const peerRaw of acc.family) {
        const peerId = String(peerRaw || "").trim().toLowerCase();
        const j = idToIndex.get(peerId);
        if (j === undefined || j === i) continue;
        const pj = quotas[j];
        if (
          pools[j] === pools[i] &&
          q.weeklyFraction !== null &&
          q.weeklyFraction < 1 &&
          pj.weeklyFraction !== null &&
          pj.weeklyFraction < 1 &&
          q.weeklyResetRawMs !== null &&
          pj.weeklyResetRawMs !== null &&
          Math.abs(q.weeklyResetRawMs - pj.weeklyResetRawMs) <= 2000
        ) {
          uf.union(i, j);
          accountTags[i].family = true;
          accountTags[j].family = true;
        }
      }
    }
  }

  const components = new Map();
  for (let i = 0; i < n; i++) {
    const root = uf.find(i);
    let list = components.get(root);
    if (!list) {
      list = [];
      components.set(root, list);
    }
    list.push(i);
  }

  let sumEffectiveWeighted = 0;
  let sumWeightEffective = 0;
  let sum5hWeighted = 0;
  let sumWeight5h = 0;
  let sum7dWeighted = 0;
  let sumWeight7d = 0;

  let minResetEffectiveMs = null;
  let minReset5hConsumedMs = null;
  let minReset5hFallbackMs = null;
  let minReset7dMs = null;
  let componentCount = 0;
  const componentSummaries = [];
  const compWeeklyByMember = new Array(n).fill(null);

  for (const members of components.values()) {
    const knownMembers = members.filter((idx) => quotas[idx].known);
    const knownBucketMembers = members.filter((idx) => quotas[idx].bucketRem !== null);
    const weight = maxOf(members.map((idx) => getTierInfo(schedulable[idx]).weight));

    const with7d = members.filter((idx) => quotas[idx].weekly !== null);
    const compWeeklyRaw = with7d.length > 0 ? minOf(with7d.map((idx) => quotas[idx].weekly)) : null;
    const compWeekly =
      compWeeklyRaw !== null ? (compWeeklyRaw <= reservePct ? 0 : compWeeklyRaw) : null;
    let compWeeklyResetMs = null;
    for (const idx of with7d) {
      const r7 = quotas[idx].reset7dMs;
      if (r7 !== null && (compWeeklyResetMs === null || r7 < compWeeklyResetMs)) {
        compWeeklyResetMs = r7;
      }
    }
    for (const idx of members) {
      compWeeklyByMember[idx] = compWeekly;
    }

    if (knownMembers.length === 0) {
      componentSummaries.push({
        members,
        knownMembers,
        knownBucketMembers,
        weight,
        compWeekly,
        compWeeklyResetMs,
      });
      continue;
    }

    componentCount++;
    const uncooledMembers = members.filter((idx) => !quotas[idx].inCooldown);
    componentSummaries.push({
      members,
      knownMembers,
      knownBucketMembers,
      weight,
      compWeekly,
      compWeeklyResetMs,
    });

    const uncooledWithBucket = uncooledMembers.filter(
      (idx) => quotas[idx].h5 !== null || compWeekly !== null,
    );

    if (uncooledMembers.length === 0) {
      sumWeightEffective += weight;
      for (const idx of members) {
        const q = quotas[idx];
        const bucketZero =
          (q.h5 !== null && q.h5 <= reservePct) ||
          (compWeekly !== null && compWeekly <= reservePct);
        const r =
          bucketZero && q.bucketResetMs !== null && q.bucketResetMs > q.cooldownMs
            ? q.bucketResetMs
            : q.cooldownMs;
        if (r !== null && (minResetEffectiveMs === null || r < minResetEffectiveMs)) {
          minResetEffectiveMs = r;
        }
      }
    } else if (uncooledWithBucket.length > 0) {
      const memberRems = uncooledWithBucket.map((idx) => {
        const q = quotas[idx];
        const h5Eff = q.h5 !== null ? (q.h5 <= reservePct ? 0 : q.h5) : null;
        return Math.min(h5Eff ?? Infinity, compWeekly ?? Infinity);
      });
      const compRem = maxOf(memberRems);
      sumEffectiveWeighted += compRem * weight;
      sumWeightEffective += weight;
      for (const idx of knownBucketMembers) {
        const r = quotas[idx].bucketResetMs;
        if (r !== null && (minResetEffectiveMs === null || r < minResetEffectiveMs)) {
          minResetEffectiveMs = r;
        }
      }
    }

    if (with7d.length > 0) {
      sum7dWeighted += compWeekly * weight;
      sumWeight7d += weight;
      if (compWeeklyResetMs !== null && (minReset7dMs === null || compWeeklyResetMs < minReset7dMs)) {
        minReset7dMs = compWeeklyResetMs;
      }
    }
  }

  // 5 hours summary: weighted average across each account's own independent 5h window
  // (constrained by its own/shared weekly exhaustion), NEVER min-merged across shared peers
  for (let idx = 0; idx < n; idx++) {
    const q = quotas[idx];
    if (q.h5 === null) continue;
    const w = getTierInfo(schedulable[idx]).weight;
    const effWeekly = compWeeklyByMember[idx] ?? q.weekly;
    const weeklyZero = effWeekly !== null && effWeekly <= reservePct;
    const h5Eff = weeklyZero || q.h5 <= reservePct ? 0 : q.h5;
    sum5hWeighted += h5Eff * w;
    sumWeight5h += w;
    if (q.reset5hMs !== null) {
      if (q.h5 < 100 && (minReset5hConsumedMs === null || q.reset5hMs < minReset5hConsumedMs)) {
        minReset5hConsumedMs = q.reset5hMs;
      }
      if (minReset5hFallbackMs === null || q.reset5hMs < minReset5hFallbackMs) {
        minReset5hFallbackMs = q.reset5hMs;
      }
    }
  }

  const rawEffRemPct =
    sumWeightEffective > 0 ? sumEffectiveWeighted / sumWeightEffective : null;
  const raw5hRemPct = sumWeight5h > 0 ? sum5hWeighted / sumWeight5h : null;
  const raw7dRemPct = sumWeight7d > 0 ? sum7dWeighted / sumWeight7d : null;
  const minReset5hMs = minReset5hConsumedMs ?? minReset5hFallbackMs;

  return {
    componentCount,
    pools,
    quotas,
    components: componentSummaries,
    usedEffective: computeUsedFromRemPct(rawEffRemPct),
    used5h: computeUsedFromRemPct(raw5hRemPct),
    used7d: computeUsedFromRemPct(raw7dRemPct),
    resetsAtEffective: safeToISOString(minResetEffectiveMs),
    resetsAt5h: safeToISOString(minReset5hMs),
    resetsAt7d: safeToISOString(minReset7dMs),
    span: sumWeight5h > 0 ? 18000 : 604800,
  };
}

function buildAliasMap(modelMapping, modelMetadataMap) {
  const aliasMap = new Map();
  if (modelMapping instanceof Map) {
    for (const [k, v] of modelMapping.entries()) {
      if (typeof k === "string" && k.trim() && typeof v === "string" && v.trim()) {
        aliasMap.set(k.trim(), v.trim());
      }
    }
  } else if (modelMapping && typeof modelMapping === "object") {
    for (const [k, v] of Object.entries(modelMapping)) {
      if (typeof k === "string" && k.trim() && typeof v === "string" && v.trim()) {
        aliasMap.set(k.trim(), v.trim());
      }
    }
  }
  if (modelMetadataMap instanceof Map) {
    for (const [id, meta] of modelMetadataMap.entries()) {
      if (meta?.isAlias && meta?.aliasTarget && !aliasMap.has(id)) {
        aliasMap.set(id, meta.aliasTarget);
      }
    }
  } else if (modelMetadataMap && typeof modelMetadataMap === "object") {
    for (const [id, meta] of Object.entries(modelMetadataMap)) {
      if (meta?.isAlias && meta?.aliasTarget && !aliasMap.has(id)) {
        aliasMap.set(id, meta.aliasTarget);
      }
    }
  }
  return aliasMap;
}

function lookupModelMeta(modelMetadataMap, id) {
  if (!modelMetadataMap || !id) return null;
  if (modelMetadataMap instanceof Map) return modelMetadataMap.get(id) ?? null;
  if (typeof modelMetadataMap === "object") return modelMetadataMap[id] ?? null;
  return null;
}

function accountSupportsModel(
  acc,
  modelId,
  accountModelsMap,
  aliasMap,
  anyPeerHasNonEmptyCatalog,
) {
  if (!accountModelsMap) return true;
  const accKey = String(acc?.id || "").trim().toLowerCase();
  const rawSet =
    accountModelsMap instanceof Map
      ? accountModelsMap.get(accKey)
      : (accountModelsMap[acc?.id] ?? accountModelsMap[accKey]);
  if (rawSet === undefined || rawSet === null) return true;
  const accSet = rawSet instanceof Set ? rawSet : Array.isArray(rawSet) ? new Set(rawSet) : null;
  if (!accSet) return true;

  if (accSet.size === 0) {
    return !(Boolean(acc?.quota_at) && anyPeerHasNonEmptyCatalog);
  }
  const effectiveId = aliasMap?.get(modelId) ?? modelId;
  const baseId = foldModelId(effectiveId).baseId;
  return (
    accSet.has(effectiveId) ||
    accSet.has(baseId) ||
    (effectiveId !== modelId && accSet.has(modelId))
  );
}

function resolveAccountModelCooldownMs(acc, modelId, nowMs, aliasMap, modelMetadataMap) {
  const effectiveId = aliasMap?.get(modelId) ?? modelId;
  const cdEffective = parseFutureMs(acc?.cooldown?.[effectiveId], nowMs);
  const cdOriginal =
    effectiveId !== modelId ? parseFutureMs(acc?.cooldown?.[modelId], nowMs) : null;
  if (cdEffective !== null || cdOriginal !== null) {
    return Math.max(cdEffective ?? 0, cdOriginal ?? 0);
  }

  if (foldModelId(effectiveId).variant !== null) {
    return null;
  }
  const meta =
    lookupModelMeta(modelMetadataMap, effectiveId) ?? lookupModelMeta(modelMetadataMap, modelId);
  const levels = Array.isArray(meta?.thinkingLevels) ? meta.thinkingLevels : [];
  if (levels.length === 0) {
    return null;
  }
  const variantCooldowns = [];
  for (const lvl of levels) {
    const vc = parseFutureMs(acc?.cooldown?.[`${effectiveId}-${lvl}`], nowMs);
    if (vc === null) {
      return null;
    }
    variantCooldowns.push(vc);
  }
  return minOf(variantCooldowns);
}

function computeModelWindowUsage(modelId, schedulable, poolAgg, nowMs, ctx = {}) {
  const { quotas, components, span: poolDefaultSpan } = poolAgg;
  if (!components || components.length === 0) return null;

  const {
    reserveFraction = 0,
    accountModelsMap = null,
    anyPeerHasNonEmptyCatalog = false,
    aliasMap = null,
    modelMetadataMap = null,
  } = ctx;
  const reservePct = reserveFraction * 100;

  let sumWeighted = 0;
  let sumWeight = 0;
  let hasUnknownUncooled = false;
  let anyAiCreditsCanServe = false;

  let loss7d = 0;
  let loss5h = 0;
  let lossCool = 0;
  const resets7dAffected = [];
  const resets5hConsumed = [];
  const resets5hFallback = [];
  const coolResets = [];
  const allEligibleMembers = [];

  for (const comp of components) {
    const { members, compWeekly, compWeeklyResetMs } = comp;
    const eligibleMembers = members.filter((idx) =>
      accountSupportsModel(
        schedulable[idx],
        modelId,
        accountModelsMap,
        aliasMap,
        anyPeerHasNonEmptyCatalog,
      ),
    );
    if (eligibleMembers.length === 0) continue;

    const compWeight = maxOf(eligibleMembers.map((idx) => getTierInfo(schedulable[idx]).weight));
    const uncooledKnown = [];
    const uncooledUnknown = [];
    const cooled = [];

    for (const idx of eligibleMembers) {
      const acc = schedulable[idx];
      const q = quotas[idx];
      const mc = resolveAccountModelCooldownMs(acc, modelId, nowMs, aliasMap, modelMetadataMap);
      const gc = q.cooldownMs;
      const isCooled = mc !== null || gc !== null;
      const h5 = q.h5 !== null ? (q.h5 <= reservePct ? 0 : q.h5) : null;
      const weekly =
        compWeekly !== null
          ? compWeekly
          : q.weekly !== null
            ? q.weekly <= reservePct
              ? 0
              : q.weekly
            : null;
      const hasKnownBucket = h5 !== null || weekly !== null;

      const info = {
        idx,
        acc,
        q,
        mc,
        gc,
        isCooled,
        h5,
        weekly,
        hasKnownBucket,
        compWeeklyResetMs,
      };
      allEligibleMembers.push(info);

      if (isCooled) {
        cooled.push(info);
      } else if (hasKnownBucket) {
        uncooledKnown.push(info);
      } else {
        uncooledUnknown.push(info);
      }
    }

    if (uncooledKnown.length > 0) {
      const compRem = maxOf(
        uncooledKnown.map((m) => Math.min(m.h5 ?? Infinity, m.weekly ?? Infinity)),
      );
      sumWeight += compWeight;
      sumWeighted += compRem * compWeight;

      if (compRem <= 0) {
        for (const m of uncooledKnown) {
          if (reserveFraction === 0 && hasUsableAiCredits(m.acc)) {
            anyAiCreditsCanServe = true;
          }
        }
        if (uncooledUnknown.length > 0) {
          hasUnknownUncooled = true;
        }
      }

      if (compRem < 100) {
        const h5Values = uncooledKnown.filter((m) => m.h5 !== null).map((m) => m.h5);
        const comp5h = h5Values.length > 0 ? maxOf(h5Values) : null;
        if (compWeekly !== null && (comp5h === null || compWeekly <= comp5h) && compWeekly < 100) {
          loss7d += (100 - compRem) * compWeight;
          let added7d = false;
          for (const m of uncooledKnown) {
            if (m.q.reset7dMs !== null && (m.weekly ?? compWeekly) < 100) {
              resets7dAffected.push(m.q.reset7dMs);
              added7d = true;
            }
          }
          if (!added7d && compWeeklyResetMs !== null) {
            resets7dAffected.push(compWeeklyResetMs);
          }
        } else if (comp5h !== null && comp5h < (compWeekly ?? Infinity) && comp5h < 100) {
          loss5h += (100 - compRem) * compWeight;
          for (const m of uncooledKnown) {
            if (m.q.reset5hMs !== null) {
              if (m.h5 !== null && m.h5 < 100) {
                resets5hConsumed.push(m.q.reset5hMs);
              }
              resets5hFallback.push(m.q.reset5hMs);
            }
          }
        }
      }
    } else if (uncooledUnknown.length > 0) {
      hasUnknownUncooled = true;
    } else if (cooled.length > 0) {
      sumWeight += compWeight;
      const all7dExhausted = cooled.every(
        (m) =>
          m.weekly !== null &&
          m.weekly <= reservePct &&
          Math.max(m.mc ?? 0, m.gc ?? 0) <= (m.q.reset7dMs ?? m.compWeeklyResetMs ?? 0) + 2000,
      );
      const all5hExhausted =
        !all7dExhausted &&
        cooled.every(
          (m) =>
            m.h5 !== null &&
            m.h5 <= reservePct &&
            Math.max(m.mc ?? 0, m.gc ?? 0) <= (m.q.reset5hMs ?? 0) + 2000,
        );
      if (all7dExhausted) {
        loss7d += 100 * compWeight;
        for (const m of cooled) {
          const r7 = m.q.reset7dMs ?? m.compWeeklyResetMs;
          if (r7 !== null) resets7dAffected.push(r7);
        }
      } else if (all5hExhausted) {
        loss5h += 100 * compWeight;
        for (const m of cooled) {
          if (m.q.reset5hMs !== null) {
            resets5hConsumed.push(m.q.reset5hMs);
            resets5hFallback.push(m.q.reset5hMs);
          }
        }
      } else {
        lossCool += 100 * compWeight;
        for (const m of cooled) {
          const coolUntil = Math.max(m.mc ?? 0, m.gc ?? 0);
          coolResets.push(coolUntil);
        }
      }
    }
  }

  if (sumWeight <= 0) return null;
  const used = computeUsedFromRemPct(sumWeighted / sumWeight);
  if (used === null) return null;
  const aside =
    used === 100 &&
    ((reserveFraction === 0 && anyAiCreditsCanServe) || hasUnknownUncooled);

  let resetsAt;
  let span = poolDefaultSpan;

  if (used === 100) {
    let minRecoverMs = Infinity;
    let winningSpan = poolDefaultSpan;

    for (const m of allEligibleMembers) {
      const blockers = [];
      if (m.h5 !== null && m.h5 <= reservePct) {
        blockers.push({ ms: m.q.reset5hMs ?? Infinity, type: "5h" });
      }
      if (m.weekly !== null && m.weekly <= reservePct) {
        blockers.push({ ms: m.q.reset7dMs ?? m.compWeeklyResetMs ?? Infinity, type: "7d" });
      }
      if (m.gc !== null) {
        blockers.push({ ms: m.gc, type: "cool" });
      }
      if (m.mc !== null) {
        blockers.push({ ms: m.mc, type: "cool" });
      }
      if (blockers.length === 0) {
        continue;
      }
      let worst = blockers[0];
      const rankType = (t) => (t === "7d" ? 2 : t === "5h" ? 1 : 0);
      for (let i = 1; i < blockers.length; i++) {
        const b = blockers[i];
        if (b.ms > worst.ms || (b.ms === worst.ms && rankType(b.type) > rankType(worst.type))) {
          worst = b;
        }
      }
      if (worst.ms < minRecoverMs) {
        minRecoverMs = worst.ms;
        winningSpan =
          worst.type === "7d" ? 604800 : worst.type === "5h" ? 18000 : poolDefaultSpan;
      }
    }

    resetsAt = Number.isFinite(minRecoverMs) ? safeToISOString(minRecoverMs) : undefined;
    span = winningSpan;
  } else if (used > 0) {
    if (loss7d > 0 && loss7d >= loss5h) {
      span = 604800;
      resetsAt = resets7dAffected.length > 0 ? safeToISOString(minOf(resets7dAffected)) : undefined;
    } else if (loss5h > 0) {
      span = 18000;
      const r5 =
        resets5hConsumed.length > 0
          ? minOf(resets5hConsumed)
          : resets5hFallback.length > 0
            ? minOf(resets5hFallback)
            : null;
      resetsAt = safeToISOString(r5);
    } else if (lossCool > 0) {
      span = poolDefaultSpan;
      resetsAt = coolResets.length > 0 ? safeToISOString(minOf(coolResets)) : undefined;
    }
  }

  return {
    used,
    resetsAt,
    span,
    aside,
  };
}

// The quota group `/api/models` gives the model (a synthetic effort variant takes its base
// model's). A model without one gets no routing window.
function resolveModelGroupKey(modelId, modelQuotaGroupMap, modelMetadataMap, aliasMap = null) {
  const lookupMap = (key) => {
    if (!modelQuotaGroupMap) return "";
    if (modelQuotaGroupMap instanceof Map) return modelQuotaGroupMap.get(key) || "";
    if (typeof modelQuotaGroupMap === "object") return modelQuotaGroupMap[key] || "";
    return "";
  };
  const lookupMeta = (key) => {
    if (!modelMetadataMap) return null;
    if (modelMetadataMap instanceof Map) return modelMetadataMap.get(key) ?? null;
    if (typeof modelMetadataMap === "object") return modelMetadataMap[key] ?? null;
    return null;
  };

  let explicit = String(lookupMap(modelId) || "").trim().toLowerCase();
  if (!explicit) {
    const meta = lookupMeta(modelId);
    if (meta?.isSynthetic && meta?.baseId) {
      explicit = String(lookupMap(meta.baseId) || "").trim().toLowerCase();
    }
  }
  if (!explicit && aliasMap?.has?.(modelId)) {
    const target = aliasMap.get(modelId);
    explicit =
      String(lookupMap(target) || lookupMap(foldModelId(target).baseId) || "")
        .trim()
        .toLowerCase();
  }
  return explicit || null;
}

function accountDisplayName(account) {
  const label = typeof account?.label === "string" ? account.label.trim() : "";
  if (label) return label;
  const name = typeof account?.name === "string" ? account.name.trim() : "";
  if (name) return name;
  const rawId = typeof account?.id === "string" ? account.id.trim() : "";
  if (rawId.includes("@")) return rawId.split("@")[0] || "account";
  return rawId || "account";
}

function accountStateLabel(account) {
  const state = String(account?.state || "").trim().toLowerCase();
  if (state === "ready") return "在线";
  if (state === "cooling") return "部分冷却";
  if (state === "pending") return "待就绪";
  if (state === "error") return "异常";
  if (state === "disabled") return "已禁用";
  return state || "未知";
}

function formatPlanSummary(schedulable, totalCount) {
  if (!Array.isArray(schedulable) || schedulable.length === 0) {
    return `0/${totalCount} 在线`;
  }
  const counts = new Map();
  for (const a of schedulable) {
    const { tier } = getTierInfo(a);
    counts.set(tier, (counts.get(tier) || 0) + 1);
  }
  const order = ["ULTRA", "PRO", "FREE"];
  const parts = [];
  for (const t of order) {
    const n = counts.get(t);
    if (n) parts.push(`${t} ×${n}`);
  }
  return parts.length > 0 ? parts.join(" + ") : `${schedulable.length}/${totalCount} 在线`;
}

function fmtPct(v) {
  return v === null || v === undefined ? "-" : `${Math.round(v)}%`;
}

function formatDedupTag(tag) {
  if (!tag) return "";
  if (tag.shared && tag.family) return "共享+家庭";
  if (tag.shared) return "共享";
  if (tag.family) return "家庭";
  return "";
}

export function computeAgy2ApiUsage(accounts, options = {}) {
  const {
    showAccountDetails = true,
    maxAccountDetails = 0,
    foldEffortVariants = false,
    discoveredModels = null,
    modelQuotaGroupMap = null,
    modelMetadataMap = null,
    modelMapping = null,
    accountModelsMap = null,
    allowedAccountIds = null,
    quotaReserveFraction = 0,
    nowMs = Date.now(),
  } = options;

  const rawList = Array.isArray(accounts) ? accounts : [];
  const list =
    allowedAccountIds instanceof Set
      ? rawList.filter((acc) => {
          const id = String(acc?.id || "").trim();
          return Boolean(id && allowedAccountIds.has(id));
        })
      : rawList;
  const reserveFraction =
    typeof quotaReserveFraction === "number" &&
    Number.isFinite(quotaReserveFraction) &&
    quotaReserveFraction >= 0 &&
    quotaReserveFraction < 1
      ? quotaReserveFraction
      : 0;
  const reservePct = reserveFraction * 100;

  const schedulable = list.filter(isSchedulableAccount);
  const schedulableIdxMap = new Map();
  schedulable.forEach((acc, idx) => schedulableIdxMap.set(acc, idx));

  const aliasMap = buildAliasMap(modelMapping, modelMetadataMap);
  let anyPeerHasNonEmptyCatalog = false;
  if (accountModelsMap) {
    const entries =
      accountModelsMap instanceof Map
        ? accountModelsMap.values()
        : Object.values(accountModelsMap);
    for (const s of entries) {
      if ((s instanceof Set && s.size > 0) || (Array.isArray(s) && s.length > 0)) {
        anyPeerHasNonEmptyCatalog = true;
        break;
      }
    }
  }

  const modelInfos = collectModelInfos(discoveredModels, foldEffortVariants, modelMetadataMap);
  const discoveredIdSet = new Set(modelInfos.map((m) => m.id));
  const pools = discoverQuotaPools(schedulable);
  const poolByKey = new Map(pools.map((p) => [p.key, p]));

  const accountTags = Array.from({ length: schedulable.length }, () => ({
    shared: false,
    family: false,
  }));

  // What is shown: one aggregate per actual pool.
  const poolAggregates = new Map();
  for (const pool of pools) {
    poolAggregates.set(
      pool.key,
      computePoolAggregate(schedulable, () => pool.key, nowMs, accountTags, reservePct),
    );
  }

  // What routing reads: one aggregate per model quota group, each account contributing the
  // pool it bills that group to. `pool` is the card pool the group's windows are filed
  // under: its own pool when accounts have one, else the pool they fall back to.
  const groupRoutings = new Map();
  const routingForGroup = (groupKey) => {
    let routing = groupRoutings.get(groupKey);
    if (!routing) {
      const agg = computePoolAggregate(
        schedulable,
        (acc) => resolveAccountPool(acc, groupKey),
        nowMs,
        accountTags,
        reservePct,
      );
      const poolKey = poolByKey.has(groupKey)
        ? groupKey
        : agg.pools.find((key) => poolByKey.has(key));
      routing = { agg, pool: poolKey ? poolByKey.get(poolKey) : null };
      groupRoutings.set(groupKey, routing);
    }
    return routing;
  };

  const windows = [];

  // 1. Non-aside per-model routing windows (NO whole-account window, NO unknown=100% hold)
  const lookupMeta = (id) => lookupModelMeta(modelMetadataMap, id);
  const modelWinCtx = {
    reserveFraction,
    accountModelsMap,
    anyPeerHasNonEmptyCatalog,
    aliasMap,
    modelMetadataMap,
  };

  for (const info of modelInfos) {
    const groupKey = resolveModelGroupKey(
      info.id,
      modelQuotaGroupMap,
      modelMetadataMap,
      aliasMap,
    );
    if (!groupKey) continue;
    const { agg, pool } = routingForGroup(groupKey);
    const poolField = pool ? { pool: pool.displayName } : {};

    const baseWin = computeModelWindowUsage(info.id, schedulable, agg, nowMs, modelWinCtx);
    if (!baseWin) continue;

    const matchedIds = [info.id];
    const extraWindows = [];
    if (foldEffortVariants) {
      const meta = lookupMeta(info.id);
      const syntheticIds = Array.isArray(meta?.syntheticVariantIds)
        ? meta.syntheticVariantIds
        : (Array.isArray(meta?.thinkingLevels) ? meta.thinkingLevels : [])
            .map((lvl) => `${info.id}-${lvl}`)
            .filter((derived) => !discoveredIdSet.has(derived));

      for (const derived of syntheticIds) {
        if (matchedIds.includes(derived)) continue;
        const synWin = computeModelWindowUsage(derived, schedulable, agg, nowMs, modelWinCtx);
        if (
          synWin &&
          synWin.used === baseWin.used &&
          synWin.resetsAt === baseWin.resetsAt &&
          synWin.span === baseWin.span &&
          synWin.aside === baseWin.aside
        ) {
          matchedIds.push(derived);
        } else if (synWin) {
          extraWindows.push({
            name: info.name,
            model: derived,
            models: [derived],
            family: info.family,
            ...poolField,
            used: synWin.used,
            ...(synWin.resetsAt ? { resetsAt: synWin.resetsAt } : {}),
            span: synWin.span,
            ...(synWin.aside ? { aside: true } : {}),
          });
        }
      }
    }

    windows.push({
      name: info.name,
      model: info.id,
      models: matchedIds,
      family: info.family,
      ...poolField,
      used: baseWin.used,
      ...(baseWin.resetsAt ? { resetsAt: baseWin.resetsAt } : {}),
      span: baseWin.span,
      ...(baseWin.aside ? { aside: true } : {}),
    });
    for (const ew of extraWindows) {
      windows.push(ew);
    }
  }

  // 2. Aside pool summary windows (with pool, NO family, NO model/models)
  let poolSummaryCount = 0;
  for (const pool of pools) {
    const agg = poolAggregates.get(pool.key);
    if (!agg) continue;

    if (agg.usedEffective === null) {
      poolSummaryCount++;
      windows.push({
        name: "配额",
        pool: pool.displayName,
        display: "未知",
        aside: true,
      });
      continue;
    }

    if (agg.used5h !== null) {
      poolSummaryCount++;
      windows.push({
        name: "5 hours",
        pool: pool.displayName,
        used: agg.used5h,
        ...(agg.resetsAt5h ? { resetsAt: agg.resetsAt5h } : {}),
        span: 18000,
        aside: true,
      });
    }
    if (agg.used7d !== null) {
      poolSummaryCount++;
      windows.push({
        name: "7 days",
        pool: pool.displayName,
        used: agg.used7d,
        ...(agg.resetsAt7d ? { resetsAt: agg.resetsAt7d } : {}),
        span: 604800,
        aside: true,
      });
    }
    if (agg.used5h === null && agg.used7d === null) {
      poolSummaryCount++;
      windows.push({
        name: "配额",
        pool: pool.displayName,
        used: agg.usedEffective,
        ...(agg.resetsAtEffective ? { resetsAt: agg.resetsAtEffective } : {}),
        span: agg.span,
        aside: true,
      });
    }
  }

  // No account has reported a bucket yet: say so once, without inventing a pool for it.
  if (pools.length === 0 && schedulable.length > 0) {
    poolSummaryCount++;
    windows.push({ name: "配额", display: "未知", aside: true });
  }

  // 3. Optional per-account detail windows, one segment per pool the account has
  // (max 1 " · " per display string)
  if (showAccountDetails && list.length > 0) {
    if (poolSummaryCount % 2 === 1) {
      windows.push({
        name: "账号池",
        display: `${schedulable.length}/${list.length} 在线`,
        aside: true,
      });
    }

    const maxLimit =
      Number.isFinite(Number(maxAccountDetails)) && Number(maxAccountDetails) > 0
        ? Math.floor(Number(maxAccountDetails))
        : 0;
    const visibleAccounts =
      maxLimit > 0 && list.length > maxLimit ? list.slice(0, maxLimit) : list;

    for (const acc of visibleAccounts) {
      const { tier } = getTierInfo(acc);
      const label = accountDisplayName(acc);
      const stateText = accountStateLabel(acc);
      const schedIdx = schedulableIdxMap.get(acc);
      const dedupText =
        schedIdx !== undefined ? formatDedupTag(accountTags[schedIdx]) : "";

      let display;
      if (stateText === "在线" || stateText === "部分冷却") {
        const segments = [];
        for (const pool of pools) {
          const q = extractAccountPoolQuota(acc, pool.key, nowMs);
          if (!q.known) continue;
          if (q.inCooldown) {
            if (q.h5 !== null && q.weekly !== null) {
              segments.push(`${pool.shortLabel} 冷却(${fmtPct(q.h5)}/${fmtPct(q.weekly)})`);
            } else {
              segments.push(`${pool.shortLabel} 冷却`);
            }
          } else if (q.h5 !== null && q.weekly !== null) {
            segments.push(`${pool.shortLabel} ${fmtPct(q.h5)}/${fmtPct(q.weekly)}`);
          } else if (q.weekly !== null) {
            segments.push(`${pool.shortLabel} ${fmtPct(q.weekly)}`);
          } else if (q.h5 !== null) {
            segments.push(`${pool.shortLabel} ${fmtPct(q.h5)}`);
          }
        }

        if (stateText === "部分冷却") {
          const prefix = dedupText ? `部分冷却(${dedupText})` : "部分冷却";
          display = segments.length > 0 ? `${prefix} · ${segments.join("  ")}` : prefix;
        } else if (dedupText) {
          display =
            segments.length > 0 ? `${segments.join("  ")} · ${dedupText}` : `在线 · ${dedupText}`;
        } else if (segments.length === 0) {
          display = "在线";
        } else if (segments.length === 1) {
          display = segments[0];
        } else {
          display = `${segments[0]} · ${segments.slice(1).join("  ")}`;
        }
      } else {
        display = stateText;
      }

      windows.push({
        name: `${label} · ${tier}`,
        display,
        aside: true,
      });
    }

    if (maxLimit > 0 && list.length > maxLimit) {
      windows.push({
        name: "其他账号",
        display: `另有 ${list.length - maxLimit} 个账号`,
        aside: true,
      });
    }
  }

  return {
    plan: formatPlanSummary(schedulable, list.length),
    windows,
  };
}

function parseAccountsPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.accounts)) return payload.accounts;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.items)) return payload.items;
  return null;
}

function abortReason(signal) {
  return signal?.reason ?? new DOMException("The operation was aborted.", "AbortError");
}

function safeQuotaErrorMessage(err) {
  if (err?.kind === "auth" || err?.kind === "rate_limit" || err?.name === "AbortError") {
    return err?.message ? String(err.message) : "Antigravity2API request aborted";
  }
  const msg = typeof err?.message === "string" ? err.message : "";
  if (msg.startsWith("Antigravity2API ")) {
    return msg;
  }
  return "Antigravity2API /api/accounts request failed";
}

export async function fetchAccountsCached(baseUrl, opts = {}) {
  const {
    apiKey = "",
    adminUsername = "admin",
    adminPassword = "",
    cacheTtlSec = 10,
    refreshOnUsage = true,
    refreshCooldownSec = 60,
    fetchImpl = globalThis.fetch,
    signal,
    nowFn = Date.now,
  } = opts;

  if (signal?.aborted) {
    throw abortReason(signal);
  }

  const root = normalizeBaseUrl(baseUrl);
  const user = String(adminUsername || "admin").trim() || "admin";
  const ttlMs = Math.max(0, Number(cacheTtlSec) || 0) * 1000;
  const refreshCooldownMs = Math.max(0, Number(refreshCooldownSec) || 0) * 1000;
  const cacheKey = buildAuthScopeKey({
    baseUrl: root,
    apiKey,
    adminUsername: user,
    adminPassword,
  });
  const nowMs = nowFn();

  const currentRefreshState = () => {
    if (!refreshOnUsage) return { refreshStatus: "ok", failedCount: 0 };
    const st = lastRefreshState.get(cacheKey);
    return {
      refreshStatus: st?.status ?? "ok",
      failedCount: st?.failedCount ?? 0,
    };
  };

  if (ttlMs > 0) {
    const cached = quotaCache.get(cacheKey);
    if (cached && nowMs - cached.fetchedAt < ttlMs) {
      return {
        accounts: cached.accounts,
        stale: false,
        fetchedAt: cached.fetchedAt,
        ...currentRefreshState(),
      };
    }
  }

  // Only coalesce calls without signal so caller cancellation stays strictly isolated
  if (!signal && inFlightFetches.has(cacheKey)) {
    return inFlightFetches.get(cacheKey).promise;
  }

  const entry = { promise: null };
  if (!signal) {
    inFlightFetches.set(cacheKey, entry);
  }

  const runPromise = (async () => {
    try {
      let refreshFailedThisRound = false;
      if (refreshOnUsage) {
        const lastAt = lastRefreshAt.get(cacheKey) ?? -Infinity;
        if (nowFn() - lastAt >= refreshCooldownMs) {
          lastRefreshAt.set(cacheKey, nowFn());
          try {
            const refreshRes = await adminFetch("/api/accounts/refresh", {
              baseUrl: root,
              adminUsername: user,
              adminPassword,
              method: "POST",
              fetchImpl,
              ...(signal ? { signal } : {}),
              timeoutMs: 15000,
              nowFn,
            });
            if (refreshRes.status === 401 || refreshRes.status === 403) {
              await refreshRes.body?.cancel?.().catch(() => {});
              const authErr = new Error(
                `Antigravity2API /api/accounts/refresh returned HTTP ${refreshRes.status}`,
              );
              authErr.kind = "auth";
              authErr.status = refreshRes.status;
              throw authErr;
            }
            if (refreshRes.ok) {
              let refreshData = null;
              try {
                refreshData = await refreshRes.json();
              } catch {
                refreshData = null;
              }
              const refreshedAccounts = Array.isArray(refreshData?.accounts)
                ? refreshData.accounts
                : null;
              const rawFailed = refreshData?.failed;
              const failedCount = Array.isArray(rawFailed)
                ? rawFailed.length
                : rawFailed && typeof rawFailed === "object"
                  ? Object.keys(rawFailed).length
                  : null;
              if (refreshedAccounts && failedCount !== null) {
                const refreshStatus = failedCount > 0 ? "partial_failure" : "ok";
                const fetchedAt = nowFn();
                lastRefreshState.set(cacheKey, { status: refreshStatus, failedCount });
                quotaCache.set(cacheKey, { fetchedAt, accounts: refreshedAccounts });
                return {
                  accounts: refreshedAccounts,
                  stale: false,
                  fetchedAt,
                  refreshStatus,
                  failedCount,
                };
              }
              refreshFailedThisRound = true;
            } else {
              await refreshRes.body?.cancel?.().catch(() => {});
              refreshFailedThisRound = true;
            }
          } catch (refreshErr) {
            if (
              refreshErr?.kind === "auth" ||
              refreshErr?.kind === "rate_limit" ||
              signal?.aborted
            ) {
              throw refreshErr;
            }
            refreshFailedThisRound = true;
          }
          if (refreshFailedThisRound) {
            lastRefreshState.set(cacheKey, { status: "refresh_failed", failedCount: 0 });
          }
        }
      }

      if (signal?.aborted) {
        throw abortReason(signal);
      }

      const res = await adminFetch("/api/accounts", {
        baseUrl: root,
        adminUsername: user,
        adminPassword,
        method: "GET",
        fetchImpl,
        ...(signal ? { signal } : {}),
        timeoutMs: 8000,
        nowFn,
      });

      if (res.status === 401 || res.status === 403) {
        await res.body?.cancel?.().catch(() => {});
        const authErr = new Error(`Antigravity2API /api/accounts returned HTTP ${res.status}`);
        authErr.kind = "auth";
        authErr.status = res.status;
        throw authErr;
      }
      if (!res.ok) {
        await res.body?.cancel?.().catch(() => {});
        const prevRefresh = refreshOnUsage ? lastRefreshState.get(cacheKey) : null;
        const msg =
          refreshFailedThisRound || prevRefresh?.status === "refresh_failed"
            ? `Antigravity2API quota refresh failed and /api/accounts returned HTTP ${res.status}`
            : `Antigravity2API /api/accounts returned HTTP ${res.status}`;
        throw new Error(msg);
      }
      let data;
      try {
        data = await res.json();
      } catch {
        throw new Error("Antigravity2API /api/accounts returned an invalid response");
      }
      const accounts = parseAccountsPayload(data);
      if (!accounts) {
        throw new Error("Antigravity2API /api/accounts returned unexpected payload shape");
      }

      const fetchedAt = nowFn();
      quotaCache.set(cacheKey, { fetchedAt, accounts });
      return {
        accounts,
        stale: false,
        fetchedAt,
        ...currentRefreshState(),
      };
    } catch (err) {
      if (err?.kind === "auth" || err?.kind === "rate_limit" || signal?.aborted) {
        if (err?.kind === "auth") {
          quotaCache.delete(cacheKey);
        }
        throw err;
      }
      const cached = quotaCache.get(cacheKey);
      if (cached) {
        return {
          accounts: cached.accounts,
          stale: true,
          fetchedAt: cached.fetchedAt,
          ...currentRefreshState(),
          error: safeQuotaErrorMessage(err),
        };
      }
      const baseMsg = safeQuotaErrorMessage(err);
      if (refreshOnUsage && lastRefreshState.get(cacheKey)?.status === "refresh_failed") {
        if (!/refresh/i.test(baseMsg)) {
          throw new Error(`Antigravity2API quota refresh failed: ${baseMsg}`);
        }
      }
      throw new Error(baseMsg);
    } finally {
      if (!signal && inFlightFetches.get(cacheKey) === entry) {
        inFlightFetches.delete(cacheKey);
      }
    }
  })();

  entry.promise = runPromise;
  return runPromise;
}

function formatStaleTime(fetchedAtMs) {
  const iso = safeToISOString(fetchedAtMs);
  return iso ? iso.slice(11, 19) + "Z" : "未知时间";
}

function extractAccountModelIdSet(payload) {
  const list = Array.isArray(payload?.models)
    ? payload.models
    : Array.isArray(payload?.data)
      ? payload.data
      : Array.isArray(payload)
        ? payload
        : null;
  if (!list) return null;
  const set = new Set();
  for (const item of list) {
    let raw = "";
    if (typeof item === "string") {
      raw = item;
    } else if (item && typeof item === "object") {
      raw = item.id ?? item.baseModelId ?? item.name ?? item.model ?? "";
    }
    if (typeof raw === "string") {
      const clean = raw.trim().replace(/^models\//, "");
      if (clean) set.add(clean);
    }
  }
  return set;
}

async function fetchAccountModelsMap(schedulable, authOpts, fetchImpl, signal, nowFn) {
  if (!Array.isArray(schedulable) || schedulable.length <= 1 || typeof fetchImpl !== "function") {
    return null;
  }
  const root = normalizeBaseUrl(authOpts.baseUrl);
  const scopeKey = buildAuthScopeKey(authOpts);
  const result = new Map();
  const queue = [];

  for (const acc of schedulable) {
    const rawId = String(acc?.id || "").trim();
    if (!rawId) continue;
    const keyLower = rawId.toLowerCase();
    const cacheKey = `${scopeKey}\0${rawId}`;
    const cached = accountModelsCache.get(cacheKey);
    if (cached && nowFn() - cached.fetchedAt < ACCOUNT_MODELS_CACHE_TTL_MS) {
      result.set(keyLower, cached.modelSet);
    } else {
      queue.push({ rawId, keyLower, cacheKey });
    }
  }

  if (queue.length === 0) {
    return result;
  }

  let cursor = 0;
  const worker = async () => {
    while (cursor < queue.length) {
      if (signal?.aborted) break;
      const item = queue[cursor++];
      const runFetch = async () => {
        try {
          const res = await adminFetch(
            `/api/accounts/${encodeURIComponent(item.rawId)}/models`,
            {
              baseUrl: root,
              adminUsername: authOpts.adminUsername,
              adminPassword: authOpts.adminPassword,
              method: "GET",
              fetchImpl,
              signal,
              timeoutMs: 4000,
              nowFn,
            },
          );
          if (!res.ok) {
            await res.body?.cancel?.().catch(() => {});
            if (res.status === 404) {
              accountModelsCache.set(item.cacheKey, { fetchedAt: nowFn(), modelSet: null });
            }
            return null;
          }
          const data = await res.json();
          const set = extractAccountModelIdSet(data);
          if (set) {
            accountModelsCache.set(item.cacheKey, { fetchedAt: nowFn(), modelSet: set });
          }
          return set;
        } catch {
          return null;
        }
      };

      let modelSet;
      if (!signal && inFlightAccountModels.has(item.cacheKey)) {
        modelSet = await inFlightAccountModels.get(item.cacheKey);
      } else {
        const p = runFetch().finally(() => {
          if (!signal && inFlightAccountModels.get(item.cacheKey) === p) {
            inFlightAccountModels.delete(item.cacheKey);
          }
        });
        if (!signal) {
          inFlightAccountModels.set(item.cacheKey, p);
        }
        modelSet = await p;
      }
      result.set(item.keyLower, modelSet);
    }
  };

  const workerCount = Math.min(ACCOUNT_MODELS_CONCURRENCY, queue.length);
  await Promise.all(Array.from({ length: workerCount }, worker));
  return result;
}

export async function getAgy2ApiUsage(params = {}) {
  const {
    baseUrl,
    apiKey = "",
    adminUsername = "admin",
    adminPassword = "",
    showAccountDetails = true,
    maxAccountDetails = 0,
    foldEffortVariants = false,
    refreshOnUsage = true,
    cacheTtlSec = 10,
    refreshCooldownSec = 60,
    discoveredModels,
    modelQuotaGroupMap,
    modelMetadataMap,
    fetchImpl = globalThis.fetch,
    signal,
    nowFn = Date.now,
  } = params;

  try {
    const result = await fetchAccountsCached(baseUrl, {
      apiKey,
      adminUsername,
      adminPassword,
      refreshOnUsage,
      cacheTtlSec,
      refreshCooldownSec,
      fetchImpl,
      signal,
      nowFn,
    });

    const authScope = { baseUrl, apiKey, adminUsername, adminPassword };
    const resolvedModels =
      discoveredModels !== undefined
        ? discoveredModels
        : getDiscoveredModels(authScope, { foldEffortVariants });
    const resolvedGroupMap =
      modelQuotaGroupMap !== undefined
        ? modelQuotaGroupMap
        : getModelQuotaGroupMap(authScope);
    const resolvedMetaMap =
      modelMetadataMap !== undefined
        ? modelMetadataMap
        : getModelMetadataMap(authScope);

    const settings = await fetchAdminSettingsCached({
      baseUrl,
      adminUsername,
      adminPassword,
      fetchImpl,
      signal,
      timeoutMs: 3000,
      nowFn,
    });
    const allowedAccountIds = resolveAllowedAccountsForApiKey(settings, apiKey);
    const filteredForModels = (Array.isArray(result.accounts) ? result.accounts : [])
      .filter((acc) => {
        if (!isSchedulableAccount(acc)) return false;
        if (!allowedAccountIds) return true;
        const id = String(acc?.id || "").trim();
        return Boolean(id && allowedAccountIds.has(id));
      });
    const accountModelsMap = await fetchAccountModelsMap(
      filteredForModels,
      authScope,
      fetchImpl,
      signal,
      nowFn,
    );

    const currentNowMs = nowFn();
    const evalNowMs =
      result.stale && Number.isFinite(result.fetchedAt) ? result.fetchedAt : currentNowMs;

    const usage = computeAgy2ApiUsage(result.accounts, {
      showAccountDetails,
      maxAccountDetails,
      foldEffortVariants,
      discoveredModels: resolvedModels,
      modelQuotaGroupMap: resolvedGroupMap,
      modelMetadataMap: resolvedMetaMap,
      modelMapping: settings?.modelMapping ?? null,
      accountModelsMap,
      allowedAccountIds,
      quotaReserveFraction: settings?.quotaReserveFraction ?? 0,
      nowMs: evalNowMs,
    });

    const staleAgeMs =
      result.stale && Number.isFinite(result.fetchedAt) ? currentNowMs - result.fetchedAt : 0;
    if (result.stale && staleAgeMs > 60_000) {
      for (const w of usage.windows) {
        if (!w.aside) {
          w.aside = true;
        }
      }
    }

    const partialSuffix =
      result.refreshStatus === "partial_failure"
        ? `部分配额刷新失败（${result.failedCount || 0} 个账号）`
        : "";

    if (result.stale) {
      usage.plan = partialSuffix
        ? `${usage.plan} (刷新失败，旧缓存；${partialSuffix})`
        : `${usage.plan} (刷新失败，旧缓存)`;
      usage.windows.unshift({
        name: "状态",
        display: partialSuffix
          ? `刷新失败 · 显示旧缓存 (${formatStaleTime(result.fetchedAt)}) · ${partialSuffix}`
          : `刷新失败 · 显示旧缓存 (${formatStaleTime(result.fetchedAt)})`,
        aside: true,
      });
    } else if (result.refreshStatus === "partial_failure") {
      usage.plan = `${usage.plan} (${partialSuffix})`;
      usage.windows.unshift({
        name: "状态",
        display: partialSuffix,
        aside: true,
      });
    } else if (result.refreshStatus === "refresh_failed") {
      usage.plan = `${usage.plan} (配额刷新失败)`;
      usage.windows.unshift({
        name: "状态",
        display: `配额刷新失败 · 显示上次额度 (${formatStaleTime(result.fetchedAt)})`,
        aside: true,
      });
    }

    return usage;
  } catch (err) {
    return { error: safeQuotaErrorMessage(err) };
  }
}
