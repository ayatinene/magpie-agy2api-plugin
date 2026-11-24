import { adminFetch, normalizeBaseUrl, passwordDigest } from "./auth.mjs";
import {
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

const quotaCache = new Map();
const inFlightFetches = new Map();
const lastRefreshAt = new Map();
const lastRefreshState = new Map();

export function clearQuotaCache() {
  quotaCache.clear();
  inFlightFetches.clear();
  lastRefreshAt.clear();
  lastRefreshState.clear();
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
export function extractAccountPoolQuota(account, poolKey, nowMs = Date.now()) {
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

  let bucketRem;
  if (weekly !== null && weekly <= 0) {
    bucketRem = 0;
  } else if (weekly !== null && h5 !== null) {
    bucketRem = Math.min(h5, weekly);
  } else {
    bucketRem = h5 ?? weekly;
  }

  const bucketResetMs =
    weekly !== null && weekly <= 0
      ? (reset7dMs ?? reset5hMs)
      : (reset5hMs ?? reset7dMs);

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
export function extractAccountGroupQuota(account, groupKey, nowMs = Date.now()) {
  const pool = resolveAccountPool(account, groupKey);
  return { pool, ...extractAccountPoolQuota(account, pool, nowMs) };
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
function computePoolAggregate(schedulable, poolOf, nowMs, accountTags) {
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
    quotas[i] = extractAccountPoolQuota(acc, pools[i], nowMs);
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
  let minReset5hMs = null;
  let minReset7dMs = null;
  let componentCount = 0;
  const componentSummaries = [];

  for (const members of components.values()) {
    const knownMembers = members.filter((idx) => quotas[idx].known);
    const knownBucketMembers = members.filter((idx) => quotas[idx].bucketRem !== null);
    const weight = maxOf(members.map((idx) => getTierInfo(schedulable[idx]).weight));
    if (knownMembers.length === 0) {
      componentSummaries.push({
        members,
        knownMembers,
        knownBucketMembers,
        weight,
        compBucketRem: null,
      });
      continue;
    }

    componentCount++;
    const compBucketRem =
      knownBucketMembers.length > 0
        ? minOf(knownBucketMembers.map((idx) => quotas[idx].bucketRem))
        : null;
    const uncooledMembers = members.filter((idx) => !quotas[idx].inCooldown);
    componentSummaries.push({
      members,
      knownMembers,
      knownBucketMembers,
      weight,
      compBucketRem,
    });

    if (uncooledMembers.length === 0) {
      sumWeightEffective += weight;
      for (const idx of members) {
        const q = quotas[idx];
        const r =
          compBucketRem !== null && compBucketRem <= 0 && q.bucketResetMs !== null && q.bucketResetMs > q.cooldownMs
            ? q.bucketResetMs
            : q.cooldownMs;
        if (r !== null && (minResetEffectiveMs === null || r < minResetEffectiveMs)) {
          minResetEffectiveMs = r;
        }
      }
    } else if (compBucketRem !== null) {
      sumEffectiveWeighted += compBucketRem * weight;
      sumWeightEffective += weight;
      for (const idx of knownBucketMembers) {
        const r = quotas[idx].bucketResetMs;
        if (r !== null && (minResetEffectiveMs === null || r < minResetEffectiveMs)) {
          minResetEffectiveMs = r;
        }
      }
    }

    const with5h = knownBucketMembers.filter((idx) => quotas[idx].h5 !== null);
    if (with5h.length > 0) {
      const comp5h = minOf(
        with5h.map((idx) => {
          const q = quotas[idx];
          return q.weekly !== null && q.weekly <= 0 ? 0 : q.h5;
        }),
      );
      sum5hWeighted += comp5h * weight;
      sumWeight5h += weight;
      for (const idx of with5h) {
        const r5 = quotas[idx].reset5hMs;
        if (r5 !== null && (minReset5hMs === null || r5 < minReset5hMs)) {
          minReset5hMs = r5;
        }
      }
    }

    const with7d = knownBucketMembers.filter((idx) => quotas[idx].weekly !== null);
    if (with7d.length > 0) {
      const comp7d = minOf(with7d.map((idx) => quotas[idx].weekly));
      sum7dWeighted += comp7d * weight;
      sumWeight7d += weight;
      for (const idx of with7d) {
        const r7 = quotas[idx].reset7dMs;
        if (r7 !== null && (minReset7dMs === null || r7 < minReset7dMs)) {
          minReset7dMs = r7;
        }
      }
    }
  }

  const rawEffRemPct =
    sumWeightEffective > 0 ? sumEffectiveWeighted / sumWeightEffective : null;
  const raw5hRemPct = sumWeight5h > 0 ? sum5hWeighted / sumWeight5h : null;
  const raw7dRemPct = sumWeight7d > 0 ? sum7dWeighted / sumWeight7d : null;

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

function computeModelWindowUsage(modelId, schedulable, poolAgg, nowMs) {
  const { quotas, components, span } = poolAgg;
  if (!components || components.length === 0) return null;

  let sumWeighted = 0;
  let sumWeight = 0;
  let minResetMs = null;
  let hasUnknownUncooled = false;
  let anyAiCreditsCanServe = false;

  for (const comp of components) {
    const { members, knownBucketMembers, weight, compBucketRem } = comp;
    const uncooledMembers = [];
    const blockedResets = [];

    for (const idx of members) {
      const acc = schedulable[idx];
      const q = quotas[idx];
      const mc = parseFutureMs(acc?.cooldown?.[modelId], nowMs);
      const gc = q.cooldownMs;
      if (mc === null && gc === null) {
        uncooledMembers.push(idx);
      } else {
        const coolUntil = Math.max(mc ?? 0, gc ?? 0);
        const effReset =
          compBucketRem !== null && compBucketRem <= 0 && q.bucketResetMs !== null && q.bucketResetMs > coolUntil
            ? q.bucketResetMs
            : coolUntil;
        blockedResets.push(effReset);
      }
    }

    if (uncooledMembers.length === 0) {
      sumWeight += weight;
      if (blockedResets.length > 0) {
        const compReset = minOf(blockedResets);
        if (minResetMs === null || compReset < minResetMs) minResetMs = compReset;
      }
    } else if (compBucketRem !== null) {
      sumWeight += weight;
      sumWeighted += compBucketRem * weight;
      if (compBucketRem <= 0) {
        for (const idx of uncooledMembers) {
          if (hasUsableAiCredits(schedulable[idx])) {
            anyAiCreditsCanServe = true;
          }
          if (quotas[idx].bucketRem === null) {
            hasUnknownUncooled = true;
          }
        }
      }
      for (const idx of knownBucketMembers) {
        const r = quotas[idx].bucketResetMs;
        if (r !== null && (minResetMs === null || r < minResetMs)) {
          minResetMs = r;
        }
      }
    } else {
      hasUnknownUncooled = true;
    }
  }

  if (sumWeight <= 0) return null;
  const used = computeUsedFromRemPct(sumWeighted / sumWeight);
  if (used === null) return null;
  const aside = used === 100 && (anyAiCreditsCanServe || hasUnknownUncooled);
  return {
    used,
    resetsAt: safeToISOString(minResetMs),
    span,
    aside,
  };
}

// The quota group `/api/models` gives the model (a synthetic effort variant takes its base
// model's). A model without one gets no routing window.
function resolveModelGroupKey(modelId, modelQuotaGroupMap, modelMetadataMap) {
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
    nowMs = Date.now(),
  } = options;

  const list = Array.isArray(accounts) ? accounts : [];
  const schedulable = list.filter(isSchedulableAccount);
  const schedulableIdxMap = new Map();
  schedulable.forEach((acc, idx) => schedulableIdxMap.set(acc, idx));

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
      computePoolAggregate(schedulable, () => pool.key, nowMs, accountTags),
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
  const lookupMeta = (id) => {
    if (!modelMetadataMap) return null;
    if (modelMetadataMap instanceof Map) return modelMetadataMap.get(id) ?? null;
    if (typeof modelMetadataMap === "object") return modelMetadataMap[id] ?? null;
    return null;
  };

  for (const info of modelInfos) {
    const groupKey = resolveModelGroupKey(info.id, modelQuotaGroupMap, modelMetadataMap);
    if (!groupKey) continue;
    const { agg, pool } = routingForGroup(groupKey);
    const poolField = pool ? { pool: pool.displayName } : {};

    const baseWin = computeModelWindowUsage(info.id, schedulable, agg, nowMs);
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
        const synWin = computeModelWindowUsage(derived, schedulable, agg, nowMs);
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
  const cacheKey = `${root}\0${user}\0${passwordDigest(adminPassword)}`;
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
              const failedObj =
                refreshData?.failed &&
                typeof refreshData.failed === "object" &&
                !Array.isArray(refreshData.failed)
                  ? refreshData.failed
                  : null;
              if (refreshedAccounts && failedObj !== null) {
                const failedCount = Object.keys(failedObj).length;
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

export async function getAgy2ApiUsage(params = {}) {
  const {
    baseUrl,
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
      adminUsername,
      adminPassword,
      refreshOnUsage,
      cacheTtlSec,
      refreshCooldownSec,
      fetchImpl,
      signal,
      nowFn,
    });

    const resolvedModels =
      discoveredModels !== undefined
        ? discoveredModels
        : getDiscoveredModels(baseUrl, { foldEffortVariants });
    const resolvedGroupMap =
      modelQuotaGroupMap !== undefined
        ? modelQuotaGroupMap
        : getModelQuotaGroupMap(baseUrl);
    const resolvedMetaMap =
      modelMetadataMap !== undefined
        ? modelMetadataMap
        : getModelMetadataMap(baseUrl);

    const usage = computeAgy2ApiUsage(result.accounts, {
      showAccountDetails,
      maxAccountDetails,
      foldEffortVariants,
      discoveredModels: resolvedModels,
      modelQuotaGroupMap: resolvedGroupMap,
      modelMetadataMap: resolvedMetaMap,
      nowMs: nowFn(),
    });

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
