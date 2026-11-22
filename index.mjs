import { DEFAULT_BASE_URL, normalizeBaseUrl, resolveAuth } from "./lib/auth.mjs";
import {
  getDiscoveredModels,
  getModelMetadataMap,
  getModelQuotaGroupMap,
  reconcileModels,
} from "./lib/models.mjs";
import { getAgy2ApiUsage } from "./lib/quota.mjs";
import { createAgy2ApiFetch } from "./lib/fetch.mjs";

export const OFFICIAL_ICON_URL =
  "https://raw.githubusercontent.com/Mag1cFall/Antigravity2API/main/web/src/assets/logo.png";

function coerceBool(val, fallback) {
  if (typeof val === "boolean") return val;
  if (typeof val === "string") {
    if (val.toLowerCase() === "true") return true;
    if (val.toLowerCase() === "false") return false;
  }
  return fallback;
}

function coerceNonNegativeNum(val, fallback) {
  if (val === undefined || val === null || val === "") return fallback;
  const n = Number(val);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function readLiveOptions(input, staticOptions) {
  const m = input?.magpie;
  const rawFromOpts =
    typeof m?.options === "function" ? (m.options("agy2api") ?? m.options()) : undefined;
  const uiOpts = rawFromOpts && typeof rawFromOpts === "object" ? rawFromOpts : {};

  const pickBool = (camelKey, snakeKey, fallback) => {
    if (staticOptions && camelKey in staticOptions) return coerceBool(staticOptions[camelKey], fallback);
    if (staticOptions && snakeKey in staticOptions) return coerceBool(staticOptions[snakeKey], fallback);
    if (snakeKey in uiOpts) return coerceBool(uiOpts[snakeKey], fallback);
    if (camelKey in uiOpts) return coerceBool(uiOpts[camelKey], fallback);
    if (typeof m?.option === "function") {
      try {
        const v = m.option.length <= 1 ? m.option(snakeKey) : m.option("agy2api", snakeKey);
        if (typeof v === "boolean") return v;
      } catch {
        // ignore
      }
    }
    return fallback;
  };

  const pickNum = (camelKey, snakeKey, fallback) => {
    if (staticOptions && camelKey in staticOptions) return coerceNonNegativeNum(staticOptions[camelKey], fallback);
    if (staticOptions && snakeKey in staticOptions) return coerceNonNegativeNum(staticOptions[snakeKey], fallback);
    if (snakeKey in uiOpts) return coerceNonNegativeNum(uiOpts[snakeKey], fallback);
    if (camelKey in uiOpts) return coerceNonNegativeNum(uiOpts[camelKey], fallback);
    if (typeof m?.option === "function") {
      try {
        const v = m.option.length <= 1 ? m.option(snakeKey) : m.option("agy2api", snakeKey);
        if (v !== undefined && v !== null) return coerceNonNegativeNum(v, fallback);
      } catch {
        // ignore
      }
    }
    return fallback;
  };

  return {
    showAccountDetails: pickBool("showAccountDetails", "show_account_details", true),
    refreshOnUsage: pickBool("refreshOnUsage", "refresh_on_usage", true),
    foldEffortVariants: pickBool("foldEffortVariants", "fold_effort_variants", false),
    preserveCacheEffort: pickBool("preserveCacheEffort", "preserve_cache_effort", true),
    cacheTtlSec: pickNum("cacheTtlSec", "cache_ttl_sec", 10),
    refreshCooldownSec: pickNum("refreshCooldownSec", "refresh_cooldown_sec", 60),
    maxAccountDetails: Math.floor(pickNum("maxAccountDetails", "max_account_details", 0)),
  };
}

async function server(input, options) {
  return {
    async config(cfg) {
      cfg.provider ??= {};
      const existing = cfg.provider.agy2api ?? {};
      const baseUrl = normalizeBaseUrl(existing.api || DEFAULT_BASE_URL);
      cfg.provider.agy2api = {
        ...existing,
        name: existing.name || "Antigravity2API",
        npm: existing.npm || "@ai-sdk/google",
        api: existing.api || `${baseUrl}/v1beta`,
        models: existing.models ?? {},
      };
    },

    provider: {
      id: "agy2api",
      async models(provider, ctx) {
        const live = readLiveOptions(input, options);
        return reconcileModels(provider, ctx, {
          foldEffortVariants: live.foldEffortVariants,
        });
      },
    },

    auth: {
      provider: "agy2api",
      single: true,
      icon: OFFICIAL_ICON_URL,
      options: [
        {
          key: "show_account_details",
          label: "Show per-account details",
          labels: { zh: "显示各账号配额明细" },
          description:
            "Show each Antigravity2API account's state, remaining share per pool, and shared/family dedup indicators.",
          descriptions: { zh: "显示每个 Antigravity2API 账号的状态、各配额池剩余比例以及共享/家庭组去重标记。" },
          default: true,
        },
        {
          key: "refresh_on_usage",
          label: "Trigger Antigravity2API quota refresh",
          labels: { zh: "刷新用量时同步刷新 Antigravity2API 配额" },
          description:
            "Trigger Antigravity2API to refresh upstream quotas before reading account usage (with 60s cooldown protection).",
          descriptions: { zh: "刷新卡片用量前先触发 Antigravity2API 拉取最新配额（带 60 秒冷却防抖）。" },
          default: true,
        },
        {
          key: "fold_effort_variants",
          label: "Fold effort-suffixed models into variants",
          labels: { zh: "折叠思考强度后缀模型为变体" },
          description:
            "Hide separate -low/-medium/-high/-xhigh models and merge them into base model variants (off by default to keep both).",
          descriptions: {
            zh: "隐藏独立的 -low/-medium/-high/-xhigh 模型，合并为基础模型的思考强度变体（默认关闭，同时保留两者）。",
          },
          default: false,
        },
        {
          key: "preserve_cache_effort",
          label: "Preserve session effort for cache hits",
          labels: { zh: "后台降档对齐会话档位（保缓存）" },
          description:
            "Keep warm-prefix auxiliary requests (lowered effort with capped max output tokens) on the session's active effort level to avoid cross-model prompt cache misses.",
          descriptions: {
            zh: "命中热缓存前缀的后台辅助请求同时降低思考档位并收紧最大输出上限时，自动对齐回会话当前档位，避免跨上游模型 ID 击穿缓存。",
          },
          default: true,
        },
      ],
      methods: [
        {
          type: "api",
          label: "Antigravity2API API Key",
          labels: { zh: "Antigravity2API 公开 API 密钥" },
          placeholder: "sk-...",
          prompts: [
            {
              type: "text",
              key: "baseUrl",
              message: "Antigravity2API base URL",
              messages: { zh: "Antigravity2API 服务地址（默认 http://127.0.0.1:8017）" },
              default: DEFAULT_BASE_URL,
              placeholder: DEFAULT_BASE_URL,
            },
            {
              type: "text",
              key: "adminUsername",
              message: "Antigravity2API admin username (optional)",
              messages: { zh: "Antigravity2API 管理员用户名（默认 admin，可选）" },
              default: "admin",
              placeholder: "admin",
              optional: true,
            },
            {
              type: "password",
              key: "adminPassword",
              message: "Antigravity2API admin password (for /api/accounts & /api/models session; optional on localhost)",
              messages: { zh: "Antigravity2API 管理员密码（用于 /api/accounts 与 /api/models 会话认证；本机免密时可留空）" },
              placeholder: "",
              optional: true,
            },
          ],
        },
      ],

      async loader(getAuth) {
        const auth = await getAuth();
        const { apiKey, baseUrl, adminUsername, adminPassword } = resolveAuth(auth);
        return {
          apiKey,
          baseURL: baseUrl,
          fetch: createAgy2ApiFetch({
            baseUrl,
            apiKey,
            adminUsername,
            adminPassword,
            getAuth,
            getOptions: () => readLiveOptions(input, options),
          }),
        };
      },

      async usage(getAuth, provider, ctx) {
        const auth = await getAuth();
        const { baseUrl, adminUsername, adminPassword } = resolveAuth(auth);
        const live = readLiveOptions(input, options);
        return getAgy2ApiUsage({
          baseUrl,
          adminUsername,
          adminPassword,
          showAccountDetails: live.showAccountDetails,
          maxAccountDetails: live.maxAccountDetails,
          foldEffortVariants: live.foldEffortVariants,
          refreshOnUsage: live.refreshOnUsage,
          cacheTtlSec: live.cacheTtlSec,
          refreshCooldownSec: live.refreshCooldownSec,
          discoveredModels:
            getDiscoveredModels(baseUrl, { foldEffortVariants: live.foldEffortVariants }) ??
            provider?.models,
          modelQuotaGroupMap: getModelQuotaGroupMap(baseUrl),
          modelMetadataMap: getModelMetadataMap(baseUrl),
          signal: ctx?.signal,
        });
      },
    },
  };
}

export default {
  id: "magpie-agy2api-plugin",
  server,
};
