# magpie-agy2api-plugin

Antigravity2API (v0.1.12+) 的 Magpie 专用 Provider 插件与提示词清洗中间件包。

## 核心特性

- **提示词清洗中间件与专属侧边栏页面 (`onProvider` + `magpie.page`)**：在 Magpie 侧边栏 **插件 → 风控提示词清洗**（`Prompt Sanitizer`）打开独立整页，提供总开关（`promptSanitizer`）、客户端身份归一化与去重（`normalize_identity`）、系统提示词隐身侧载（`sideload_mode`：`off` / `auto` / `always`，默认 `off` 以契合 `Antigravity2API` `SYSTEM_PROMPT=full` 的 `<USER_REQUEST>` 封装，支持三段式分段控件按需切换）、工具描述清洗（`sanitize_tools_description`）、自定义 / 12 条推荐预设改写规则的增删改排序与一键恢复预设；页面底部固定保存 / 还原栏，保存后热更新生效；同时兼容通过 Plugins → Options JSON 编辑。
  - **「重置为 AGT beta 最新规则」（在线）**：页面经 `magpie.page.service`（本机 `127.0.0.1:18417`，端口可由 `pageServicePort` 选项调整）托管后，一键通过 `GET api/upstream-presets` 拉取 Antigravity-Manager `beta` 分支最新推荐规则，并将 4 个开关复位为默认开启、`sideload_mode` 复位为 `off`；结果先载入草稿供检查，点击「保存并生效」才会应用，也可点击「还原」撤销。拉取失败时草稿保持不变并提示错误。未经服务代理（静态页面）访问时该按钮禁用。
  - **「恢复本地预设」（离线）**：无需联网，将 4 个开关全部开启、`sideload_mode` 复位为 `off` 并恢复内置 12 条推荐规则，可作为在线拉取失败时的兜底。
  - 静态页面加载后会通过 `magpie.service` 自动无缝跳转到服务托管页（`ui/service-bridge.js` 提供与 Magpie `pagebridge.js` 一致的 `postMessage` 桥）。

- **管理员会话认证 (`POST /api/session`)**：自动使用 `adminUsername` / `adminPassword` 登录换取 `antigravity_admin` Cookie（11 小时缓存、并发登录合并、`401` 自动重登、登录 `429` `Retry-After` 退避防抖），同时支持本机免密访问。
- **全动态模型发现**：优先从管理接口 `GET /api/models` 读取完整模型元数据（`quota_group`、`thinking_levels`、`default_thinking_level`、上下文与输出上限、多模态能力），并支持无管理凭证时自动回退至公开 `GET /v1/models` + `GET /v1beta/models`。零写死模型白名单。
- **多协议自动分流与透传**：
  - `claude-*` / `MODEL_PROVIDER_ANTHROPIC` -> `@ai-sdk/anthropic` (`/v1/messages`)
  - `gemini-*` / `imagen-*` / `MODEL_PROVIDER_GOOGLE` -> `@ai-sdk/google` (`/v1beta/models/...`)
  - `gpt-*` / `MODEL_PROVIDER_OPENAI` -> `@ai-sdk/openai-compatible` (`/v1/chat/completions` 与 `/v1/responses`)
- **动态 `xhigh` 思考强度透传**：仅对 `thinking_levels` 包含 `xhigh` 的 Gemini 模型将 `X-Magpie-Effort: xhigh` 改写为 `generationConfig.thinkingConfig.thinkingLevel = "xhigh"`（同时清理冲突的 `thinkingBudget`）。
- **全 4 协议缓存亲和思考档位对齐 (`preserve_cache_effort`)**：覆盖 `gemini`、`anthropic`、`chat`（`/v1/chat/completions`）与 `responses`（`/v1/responses`）四种协议；命中热缓存前缀的后台辅助请求同时降低思考档位并收紧输出上限时，自动对齐回会话当前档位，避免跨上游模型 ID 击穿提示词缓存。
- **精细化故障隔离规范化**：
  - `429`：确保精确模型 ID 完整词元与配额语义，保留 `Retry-After`。
  - `503` / `529`：严格区分服务级不可用（如 `No ready accounts`、`server shutting down`，原样透传供 Magpie 判定节点故障）与模型级过载（`529` 或明确 `overloaded`/`capacity` 语义，保留真实状态码并精准隔离单模型）。
  - `400` 内容拒绝：针对 OpenAI / Anthropic / Gemini 的上游内容审查拒绝注入 Magpie `policyRefusal` 识别字段，避免触发误判限流冷却。
- **共享 / 家庭组去重配额统计**：
  - 支持 `ready` 与 `cooling` 状态账号（单池冷却不影响其他健康配额池）。
  - 动态发现配额池（`Gemini`、`Claude & GPT`、`Gemini 4 Argon` 及未来新增池），支持 Ultra / Ultra-lite 账号的 Argon -> Gemini 桶映射。
  - 通过并查集对 `shared[group]` 与 `family`（已启动周桶 `< 1` 且 `reset_time` 相差 `<= 2s`）自动去重，不重复计入池加权容量。
  - 未知配额不误判为 `100%` 已用，请求失败时如有旧缓存则显式提示旧缓存状态。

## 安装

```bash
magpie plugin add github:ayatinene/magpie-agy2api-plugin
# 或本地目录安装
magpie plugin add /path/to/magpie-agy2api-plugin
```

## 登录配置

在 Magpie Web UI 或 CLI 中添加 **Antigravity2API** 登录：

1. **Antigravity2API 公开 API 密钥 (`apiKey`)**：填写用于 `/v1/*` 与 `/v1beta/*` 推理请求的公开 API Key。
2. **Antigravity2API 服务地址 (`baseUrl`)**：本机默认 `http://127.0.0.1:8017`（容器部署按实际服务地址填写）。
3. **Antigravity2API 管理员用户名 (`adminUsername`，可选)**：默认 `admin`。
4. **Antigravity2API 管理员密码 (`adminPassword`，可选)**：用于 `/api/accounts` 与 `/api/models` 会话认证；本机免密开启时可留空。

## 插件选项

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `show_account_details` | `true` | 是否在用量面板中展示各账号状态、各池剩余比例及共享/家庭组去重标记 |
| `refresh_on_usage` | `true` | 查询用量前触发 `POST /api/accounts/refresh` 刷新配额（带冷却防抖） |
| `fold_effort_variants` | `false` | 是否折叠隐藏 `-low/-medium/-high/-xhigh` 后缀模型，仅保留基础模型变体 |
| `preserve_cache_effort` | `true` | 热缓存前缀后台辅助降档请求自动对齐回会话当前思考档位 |
| `cache_ttl_sec` | `10` | `/api/accounts` 短时缓存防抖秒数（`0` 关闭缓存） |
| `refresh_cooldown_sec` | `60` | 触发 `/api/accounts/refresh` 的最小冷却秒数 |
| `max_account_details` | `0` | 最多展示的账号明细条数，`0` 表示不限制 |
| `promptSanitizer` | `true` | 是否启用 Gateway `onProvider` 提示词清洗中间件（支持侧边栏「风控提示词清洗」页面切换） |
| `promptRewrite.enabled` | `true` | 是否启用自定义 / 预设改写规则列表 |
| `promptRewrite.normalize_identity` | `true` | 是否归一化第三方客户端身份声明并去重官方身份 |
| `promptRewrite.sideload_mode` | `"off"` | 系统提示词隐身侧载模式：`"off"`（默认，保留原生 `systemInstruction` 权限，契合 `Antigravity2API` `SYSTEM_PROMPT=full`）/ `"auto"`（超过 300 字节或含指令关键词时自动侧载至首轮用户消息 `<system-instruction>`）/ `"always"`（始终侧载） |
| `promptRewrite.sanitize_tools_description` | `true` | 是否清洗工具描述文本（不改动工具名与参数 Schema） |
| `promptRewrite.rules` | 12 条预设 | 自定义 glob 改写规则数组（每条含 `id`/`pattern`/`replacement`/`scope`/`enabled`，上限 64 条） |

## 测试

```bash
node --test tests/*.test.mjs
```

## License

MIT
