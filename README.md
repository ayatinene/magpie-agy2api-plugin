# magpie-agy2api-plugin

Antigravity2API (v0.1.12+) 的 Magpie 专用 Provider 插件与提示词清洗中间件包。

## 核心特性

- **提示词清洗中间件与专属侧边栏页面 (`onProvider` + `fetch` + `magpie.page`)**：提示词清洗使用同一份选项在两处执行——Magpie 的 `onProvider` 中间件（`middleware.mjs`）以及 Provider 的 `fetch`（`lib/fetch.mjs` 调用 `lib/sanitize-request.mjs`）。由于 Magpie 给中间件设置了 250ms 时限（超时会按未安装处理直接发送原文），`fetch` 中的无时限清洗可确保大请求不被漏洗；清洗本身幂等，已被中间件处理过的请求再次执行不会改变。在 Magpie 侧边栏 **插件 → 风控提示词清洗**（`Prompt Sanitizer`）可打开独立整页，提供总开关（`promptSanitizer`）、客户端身份归一化与去重（`normalize_identity`）、系统提示词隐身侧载（`sideload_mode`：`off` / `auto` / `always`，默认 `off` 以契合 `Antigravity2API` `SYSTEM_PROMPT=full` 的 `<USER_REQUEST>` 封装，支持三段式分段控件按需切换）、工具描述清洗（`sanitize_tools_description`）、自定义 / 12 条推荐预设改写规则的增删改排序与一键恢复预设；页面底部固定保存 / 还原栏，保存后热更新生效；读取设置失败时禁止保存并给出提示与「重试」按钮；同时兼容通过 Plugins → Options JSON 编辑。
  - **「拉取 Antigravity Tools 最新规则」（`Fetch latest Antigravity Tools rules`，在线）**：页面经 `magpie.page.service`（本机 `127.0.0.1:18417`，端口可由 `pageServicePort` 选项调整，修改端口后旧端口自动关闭，`disablePageService: true` 可停掉已在运行的服务）托管后，点击并经二次确认，通过 `GET api/upstream-presets` 拉取 Antigravity-Manager 仓库 `beta` 分支最新推荐规则（服务端缓存 60 秒），将 4 个开关复位为默认开启、`sideload_mode` 复位为 `off`；上游规则采用严格解析，只要存在任一无法识别的条目、总数超过 64 条、`id` 重复或字段超长，即整体报错且不改动当前草稿；拉取期间若草稿已被修改则不覆盖并给出提示，拉到的规则与已保存设置一致时提示无需保存；结果载入草稿后需点击「保存并生效」才会应用，也可点击「还原」撤销。未经服务代理（静态页面）访问时该按钮禁用。
  - **「恢复本地预设」（离线）**：无需联网，点击并经二次确认后，将 4 个开关全部开启、`sideload_mode` 复位为 `off` 并恢复内置 12 条推荐规则，可作为在线拉取失败时的兜底。
  - 静态页面加载后会通过 `magpie.service` 自动无缝跳转到服务托管页（`ui/service-bridge.js` 提供与 Magpie `pagebridge.js` 一致的 `postMessage` 桥）。

- **管理员会话认证 (`POST /api/session`)**：自动使用 `adminUsername` / `adminPassword` 登录换取 `antigravity_admin` Cookie（11 小时缓存、按密码隔离进行中的登录与配额缓存、并发登录合并、`401` 自动重登、登录被拒后 60 秒内不重复尝试、登录 `429` `Retry-After` 退避防抖），同时支持本机免密访问；认证被拒时不回退展示旧账号明细。
- **全动态模型发现**：优先从管理接口 `GET /api/models` 读取完整模型元数据（`quota_group`、`thinking_levels`、`default_thinking_level`、上下文与输出上限、多模态能力），管理接口成功返回空目录时视为有效结果；无管理凭证或管理接口不可用时自动回退至公开 `GET /v1/models` + `GET /v1beta/models`（读取 camelCase 字段并自动翻页）。零写死模型白名单。
- **多协议自动分流与透传**：目录条目带 `provider` 字段时以该字段为准选择协议，否则按模型名前缀分流：
  - `claude-*` / `MODEL_PROVIDER_ANTHROPIC` -> `@ai-sdk/anthropic` (`/v1/messages`)
  - `gemini-*` / `imagen-*` / `MODEL_PROVIDER_GOOGLE` -> `@ai-sdk/google` (`/v1beta/models/...`)
  - `gpt-*` / `MODEL_PROVIDER_OPENAI` -> `@ai-sdk/openai-compatible` (`/v1/chat/completions` 与 `/v1/responses`)
- **动态 `xhigh` 思考强度透传**：仅对 `thinking_levels` 包含 `xhigh` 的 Gemini 模型将 `X-Magpie-Effort: xhigh` 改写为 `generationConfig.thinkingConfig.thinkingLevel = "xhigh"`，同时删除冲突的 `thinkingBudget`（不强制设置 `includeThoughts`）。
- **全 4 协议缓存亲和思考档位对齐 (`preserve_cache_effort`)**：覆盖 `gemini`、`anthropic`、`chat`（`/v1/chat/completions`）与 `responses`（`/v1/responses`）四种协议；命中热缓存前缀的后台辅助请求同时降低思考档位并收紧输出上限时，仅改写请求中已有的思考档位字段以对齐回会话当前档位（不改动输出上限等其他参数），避免跨上游模型 ID 击穿提示词缓存。显式关闭思考的请求不参与对齐；状态按 Magpie 会话与 API Key 隔离，且仅在上游返回成功后才记录会话档位。
- **精细化故障隔离规范化**：未命中任何规则的错误响应保持原始字节透传。
  - `429`：仅当存在明确的额度耗尽原因（`QUOTA_EXHAUSTED`、`INSUFFICIENT_G1_CREDITS_BALANCE`）时按模型级额度错误规范化并保留 `Retry-After`；“没有可用账号”等场景原样透传。
  - `503` / `529`：严格区分服务级不可用（如 `No ready accounts`、`server shutting down`，原样透传供 Magpie 判定节点故障）与模型级过载（`529` 或明确 `overloaded`/`capacity` 语义，保留真实状态码并精准隔离单模型）。
  - `400` 内容拒绝：针对 OpenAI / Anthropic / Gemini 的上游内容审查拒绝（含上游固定的 `Upstream rejected the input: SAFETY|BLOCKLIST|PROHIBITED_CONTENT` 形态）注入 Magpie `policyRefusal` 识别字段，避免触发误判限流冷却。
- **共享 / 家庭组去重配额统计**：
  - 支持 `ready` 与 `cooling` 状态账号（单池冷却不影响其他健康配额池，模型级冷却计入对应模型，重置时间已过的桶按已恢复处理，账号仍有可用 AI 积分时不报耗尽）。
  - 配额池按可调度账号在 `GET /api/accounts` 中实际返回的额度桶动态发现（`gemini-5h`、`gemini-weekly` 属于 `Gemini` 池，`3p-*` 属于 `Claude & GPT` 池）。池汇总与账号明细只展示账号实际拥有的池，不按模型的 `quota_group` 生成：没有账号返回独立 Argon 桶时不会出现 `Gemini 4 Argon` 池，只有部分账号有时该池只统计这些账号。
  - 模型的 `quota_group` 只用于各模型的路由用量窗，由每个账号解析到它实际扣减的池：账号没有独立 Argon 桶而有 Gemini 桶时，Argon 模型计入该账号的 Gemini 池（与 Antigravity2API 的调度规则一致），因此独立 Argon 桶与共用 Gemini 桶的账号可以并存。没有 `quota_group` 的模型不生成用量窗。
  - 通过并查集对 `shared[池]` 与 `family`（已启动周桶 `< 1` 且 `reset_time` 相差 `<= 2s`）自动去重，只合并从同一个池扣减的账号，不重复计入池加权容量。
  - 剩余配额为正时已用百分比最高显示 `99%`，未知配额不误判为 `100%` 已用；配额刷新失败、部分失败或回退旧缓存时均给出明确提示。

## 安装

```bash
magpie plugin add github:ayatinene/magpie-agy2api-plugin
# 或本地目录安装
magpie plugin add /path/to/magpie-agy2api-plugin
```

## 登录配置

在 Magpie Web UI 或 CLI 中添加 **Antigravity2API** 登录：

1. **Antigravity2API 公开 API 密钥 (`apiKey`)**：填写用于 `/v1/*` 与 `/v1beta/*` 推理请求的公开 API Key。
2. **Antigravity2API 服务地址 (`baseUrl`)**：本机默认 `http://127.0.0.1:8017`（容器部署按实际服务地址填写；地址生效优先级：登录时填写的 `baseUrl` > Provider 配置中的 `api` > 默认地址）。
3. **Antigravity2API 管理员用户名 (`adminUsername`，可选)**：默认 `admin`。
4. **Antigravity2API 管理员密码 (`adminPassword`，可选)**：用于 `/api/accounts` 与 `/api/models` 会话认证；本机免密开启时可留空。

## 插件选项

界面（Web UI）中保存的动态选项值优先于静态配置选项；以下选项同时兼容 `snake_case` 与 `camelCase` 键名（表格列出 `package.json` `magpie.options` 与 `auth.options` 对应键名）：

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `show_account_details` (`showAccountDetails`) | `true` | 是否在用量面板中展示各账号状态、各池剩余比例及共享/家庭组去重标记 |
| `refresh_on_usage` (`refreshOnUsage`) | `true` | 查询用量前触发 `POST /api/accounts/refresh` 刷新配额（带冷却防抖） |
| `fold_effort_variants` (`foldEffortVariants`) | `false` | 是否隐藏插件根据“基础模型 + 声明档位”生成的 `-low/-medium/-high/-xhigh` 后缀项（上游目录中真实存在的后缀 ID 或别名始终保留） |
| `preserve_cache_effort` (`preserveCacheEffort`) | `true` | 热缓存前缀后台辅助降档请求仅将已有思考档位字段对齐回会话当前档位（显式关闭思考的请求不参与，按会话与 API Key 隔离，上游成功后记录） |
| `cache_ttl_sec` (`cacheTtlSec`) | `10` | `/api/accounts` 短时缓存防抖秒数（`0` 关闭缓存） |
| `refresh_cooldown_sec` (`refreshCooldownSec`) | `60` | 触发 `/api/accounts/refresh` 的最小冷却秒数 |
| `max_account_details` (`maxAccountDetails`) | `0` | 最多展示的账号明细条数，`0` 表示不限制 |
| `pageServicePort` | `18417` | 侧边栏设置页本机服务监听端口（`127.0.0.1`，修改后旧端口自动关闭；设为 `disablePageService: true` 可停用本机页面服务） |
| `promptSanitizer` | `true` | 是否启用提示词清洗（同时作用于 Gateway `onProvider` 中间件与 Provider `fetch`，支持侧边栏「风控提示词清洗」页面切换） |
| `promptRewrite.enabled` | `true` | 是否启用自定义 / 预设改写规则列表 |
| `promptRewrite.normalize_identity` | `true` | 是否归一化第三方客户端身份声明并去重官方身份 |
| `promptRewrite.sideload_mode` | `"off"` | 系统提示词隐身侧载模式：`"off"`（默认，保留原生 `systemInstruction` 权限，契合 `Antigravity2API` `SYSTEM_PROMPT=full`）/ `"auto"`（超过 300 字节或含指令关键词时自动侧载至首轮用户消息 `<system-instruction>`）/ `"always"`（始终侧载） |
| `promptRewrite.sanitize_tools_description` | `true` | 是否清洗工具描述文本（不改动工具名与参数 Schema） |
| `promptRewrite.rules` | 12 条预设 | 自定义 glob 改写规则数组（每条含 `id`/`pattern`/`replacement`/`scope`/`enabled`，上限 64 条） |

## 测试

```bash
node --test --test-concurrency=1 tests/*.test.mjs
```

- `tests/agt-parity.test.mjs` 逐条移植了 Antigravity-Manager 仓库 `beta` 分支 `prompt_sanitizer.rs` 中的 89 个 `#[test]` 用例，用于校验提示词清洗结果与 Antigravity Tools 原版一致。
- `tools/moejs-bench/`：在 Magpie 实际使用的 `moejs` 引擎中运行 `middleware.mjs`，验证每个用例在 250ms 预算内完成且输出与 Node 一致（需 Go 1.26+）：

```bash
cd tools/moejs-bench
node gen-corpus.mjs /tmp/corpus.ndjson
go run . ../.. /tmp/corpus.ndjson        # 可选第三个参数：预算毫秒数，默认 250
```

## License

[CC BY-NC-SA 4.0](LICENSE)，与上游 Antigravity-Manager 一致。

提示词清洗（`lib/sanitizer.mjs`）与 `tests/agt-parity.test.mjs` 移植自 [lbjlaq/Antigravity-Manager](https://github.com/lbjlaq/Antigravity-Manager) `beta` 分支的 `prompt_sanitizer.rs`（CC BY-NC-SA 4.0），由 Rust 改写为 JavaScript 并有修改。
