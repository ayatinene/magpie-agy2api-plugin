import crypto from "node:crypto";
import { DEFAULT_BASE_URL, normalizeBaseUrl, resolveAuth } from "./lib/auth.mjs";
import {
  ensureModelsDiscovered,
  getDiscoveredModels,
  getModelMetadataMap,
  getModelQuotaGroupMap,
  reconcileModels,
} from "./lib/models.mjs";
import { getAgy2ApiUsage } from "./lib/quota.mjs";
import { createAgy2ApiFetch } from "./lib/fetch.mjs";
import {
  DEFAULT_PAGE_SERVICE_PORT,
  startPageService,
  stopPageService,
} from "./lib/page-service.mjs";

export const OFFICIAL_ICON_URL =
  "https://raw.githubusercontent.com/Mag1cFall/Antigravity2API/main/web/src/assets/logo.png";

function tryCoerceBool(val) {
  if (typeof val === "boolean") return val;
  if (typeof val === "string") {
    const trimmed = val.trim().toLowerCase();
    if (trimmed === "true") return true;
    if (trimmed === "false") return false;
  }
  return undefined;
}

function tryCoerceNonNegativeNum(val) {
  if (typeof val === "number") {
    return Number.isFinite(val) && val >= 0 ? val : undefined;
  }
  if (typeof val === "string") {
    if (!val.trim()) return undefined;
    const n = Number(val);
    return Number.isFinite(n) && n >= 0 ? n : undefined;
  }
  return undefined;
}

async function resolveSafe(accessor) {
  try {
    return await accessor();
  } catch {
    return undefined;
  }
}

function asOptionsObject(raw) {
  return raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
}

function createOptionReader(input, staticOptions) {
  const m = input?.magpie;
  let nsLoaded = false;
  let nsObj = {};
  let rootLoaded = false;
  let rootObj = {};

  const getNs = async () => {
    if (!nsLoaded) {
      nsLoaded = true;
      const raw =
        typeof m?.options === "function" ? await resolveSafe(() => m.options("agy2api")) : undefined;
      nsObj = asOptionsObject(raw) ?? {};
    }
    return nsObj;
  };

  const getRoot = async () => {
    if (!rootLoaded) {
      rootLoaded = true;
      const raw =
        typeof m?.options === "function" ? await resolveSafe(() => m.options()) : undefined;
      rootObj = asOptionsObject(raw) ?? {};
    }
    return rootObj;
  };

  const readSingleOption = async (key) => {
    if (typeof m?.option !== "function") return undefined;
    return resolveSafe(() => (m.option.length <= 1 ? m.option(key) : m.option("agy2api", key)));
  };

  return async function pick(camelKey, snakeKey, coerce, fallback) {
    const ns = await getNs();
    if (snakeKey in ns) {
      const v = coerce(ns[snakeKey]);
      if (v !== undefined) return v;
    }
    const root = await getRoot();
    if (snakeKey in root) {
      const v = coerce(root[snakeKey]);
      if (v !== undefined) return v;
    }
    if (typeof m?.option === "function") {
      const v = coerce(await readSingleOption(snakeKey));
      if (v !== undefined) return v;
    }

    if (camelKey in ns) {
      const v = coerce(ns[camelKey]);
      if (v !== undefined) return v;
    }
    if (camelKey in root) {
      const v = coerce(root[camelKey]);
      if (v !== undefined) return v;
    }
    if (typeof m?.option === "function") {
      const v = coerce(await readSingleOption(camelKey));
      if (v !== undefined) return v;
    }

    if (staticOptions && typeof staticOptions === "object") {
      if (snakeKey in staticOptions) {
        const v = coerce(staticOptions[snakeKey]);
        if (v !== undefined) return v;
      }
      if (camelKey in staticOptions) {
        const v = coerce(staticOptions[camelKey]);
        if (v !== undefined) return v;
      }
    }
    return fallback;
  };
}

async function readLiveOptions(input, staticOptions) {
  const pick = createOptionReader(input, staticOptions);

  return {
    showAccountDetails: await pick("showAccountDetails", "show_account_details", tryCoerceBool, true),
    refreshOnUsage: await pick("refreshOnUsage", "refresh_on_usage", tryCoerceBool, true),
    foldEffortVariants: await pick("foldEffortVariants", "fold_effort_variants", tryCoerceBool, false),
    preserveCacheEffort: await pick("preserveCacheEffort", "preserve_cache_effort", tryCoerceBool, true),
    cacheTtlSec: await pick("cacheTtlSec", "cache_ttl_sec", tryCoerceNonNegativeNum, 10),
    refreshCooldownSec: await pick("refreshCooldownSec", "refresh_cooldown_sec", tryCoerceNonNegativeNum, 60),
    maxAccountDetails: Math.floor(
      await pick("maxAccountDetails", "max_account_details", tryCoerceNonNegativeNum, 0),
    ),
  };
}

const PAGE_SERVICE_RETRY_MAX_MS = 3000;
const PAGE_SERVICE_RETRY_LIMIT = 210;
let pageServiceRun = 0;

// A reload starts this host while the previous one may still be finishing streamed replies
// and holding the port. A refused start is therefore retried (for about ten minutes) until
// that host is gone; a later `server()` call takes over from an earlier loop.
async function startPageServiceWhenFree(port) {
  const run = ++pageServiceRun;
  for (let attempt = 0; attempt < PAGE_SERVICE_RETRY_LIMIT && run === pageServiceRun; attempt += 1) {
    const started = await startPageService({ port }).catch(() => null);
    if (started?.ok || run !== pageServiceRun) return;
    const delayMs = Math.min(PAGE_SERVICE_RETRY_MAX_MS, 250 * 2 ** Math.min(attempt, 4));
    await new Promise((resolve) => {
      setTimeout(resolve, delayMs).unref?.();
    });
  }
}

async function server(input, options) {
  if (options?.disablePageService === true) {
    pageServiceRun += 1;
    await stopPageService().catch(() => {});
  } else {
    const rawPort = Number(options?.pageServicePort);
    const port =
      Number.isInteger(rawPort) && rawPort >= 1 && rawPort <= 65535
        ? rawPort
        : DEFAULT_PAGE_SERVICE_PORT;
    void startPageServiceWhenFree(port);
  }

  let configuredBaseUrl = DEFAULT_BASE_URL;

  return {
    async config(cfg) {
      cfg.provider ??= {};
      const existing = cfg.provider.agy2api ?? {};
      const baseUrl = normalizeBaseUrl(existing.api || DEFAULT_BASE_URL);
      configuredBaseUrl = baseUrl;
      cfg.provider.agy2api = {
        ...existing,
        name: existing.name || "Antigravity2API",
        npm: existing.npm || "@ai-sdk/google",
        api: existing.api || `${baseUrl}/v1beta`,
        models: existing.models ?? {},
      };
    },

    "chat.headers": async (hookInput, output) => {
      if (!output || typeof output !== "object") {
        return;
      }
      const providerID = hookInput?.model?.providerID;
      if (providerID !== "agy2api" && providerID !== "agy2api-plugin") {
        return;
      }
      const sid = hookInput?.sessionID;
      if (typeof sid === "string" && sid.trim()) {
        output.headers ??= {};
        output.headers["x-agy2api-cache-session"] = crypto
          .createHash("sha256")
          .update(sid.trim())
          .digest("hex");
      }
    },

    provider: {
      id: "agy2api",
      async models(provider, ctx) {
        const live = await readLiveOptions(input, options);
        const fallbackBaseUrl =
          typeof provider?.api === "string" && provider.api.trim()
            ? normalizeBaseUrl(provider.api)
            : configuredBaseUrl;
        return reconcileModels(provider, ctx, {
          foldEffortVariants: live.foldEffortVariants,
          defaultBaseUrl: fallbackBaseUrl,
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
            "Hide plugin-generated effort-suffixed models while keeping upstream standalone IDs/aliases.",
          descriptions: {
            zh: "隐藏插件生成的思考强度后缀项，保留上游独立 ID/别名。",
          },
          default: false,
          filtersModels: true,
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

      async loader(getAuth, provider) {
        const auth = await getAuth();
        const fallbackBaseUrl =
          typeof provider?.api === "string" && provider.api.trim()
            ? normalizeBaseUrl(provider.api)
            : configuredBaseUrl;
        const { apiKey, baseUrl, adminUsername, adminPassword } = resolveAuth(auth, {
          defaultBaseUrl: fallbackBaseUrl,
        });
        return {
          apiKey,
          baseURL: baseUrl,
          fetch: createAgy2ApiFetch({
            baseUrl,
            defaultBaseUrl: fallbackBaseUrl,
            apiKey,
            adminUsername,
            adminPassword,
            getPreserveCacheEffort: () =>
              createOptionReader(input, options)(
                "preserveCacheEffort",
                "preserve_cache_effort",
                tryCoerceBool,
                true,
              ),
            getAuth,
            getPluginOptions: () => options,
          }),
        };
      },

      async usage(getAuth, provider, ctx) {
        const auth = await getAuth();
        const fallbackBaseUrl =
          typeof provider?.api === "string" && provider.api.trim()
            ? normalizeBaseUrl(provider.api)
            : configuredBaseUrl;
        const { apiKey, baseUrl, adminUsername, adminPassword } = resolveAuth(auth, {
          defaultBaseUrl: fallbackBaseUrl,
        });
        const authScope = { baseUrl, apiKey, adminUsername, adminPassword };
        const live = await readLiveOptions(input, options);
        if (!getDiscoveredModels(authScope)) {
          await ensureModelsDiscovered(authScope, undefined, {
            signal: ctx?.signal,
            timeoutMs: 4000,
            foldEffortVariants: live.foldEffortVariants,
          }).catch(() => null);
        }
        return getAgy2ApiUsage({
          baseUrl,
          apiKey,
          adminUsername,
          adminPassword,
          showAccountDetails: live.showAccountDetails,
          maxAccountDetails: live.maxAccountDetails,
          foldEffortVariants: live.foldEffortVariants,
          refreshOnUsage: live.refreshOnUsage,
          cacheTtlSec: live.cacheTtlSec,
          refreshCooldownSec: live.refreshCooldownSec,
          discoveredModels:
            getDiscoveredModels(authScope, { foldEffortVariants: live.foldEffortVariants }) ??
            provider?.models,
          modelQuotaGroupMap: getModelQuotaGroupMap(authScope),
          modelMetadataMap: getModelMetadataMap(authScope),
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
