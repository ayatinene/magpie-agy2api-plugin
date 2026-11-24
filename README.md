# magpie-agy2api-plugin

Antigravity2API (v0.1.12+) 的 Magpie 专用 Provider 插件与提示词清洗中间件包。

## 核心特性

- **提示词清洗中间件与专属侧边栏页面 (`onProvider` + `fetch` + `magpie.page`)**：提示词清洗使用同一份选项。当请求通过本插件自身的 Provider 账号（`ctx.provider.account === "plugin"`，兼容 `"agy2api"` 与 `"agy2api-plugin"`）发送时，`middleware.mjs`（`onProvider`）会跳过二次预洗，直接由 `lib/fetch.mjs` 在最终线协议上**唯一执行一次**无 250ms 时限的 `sanitizeRequestBody`，既确保大请求不被漏洗，也消除双遍清洗带来的非幂等漂移；直连自定义 Provider 时 `onProvider` 仍照常执行清洗。在 Magpie 侧边栏 **插件 → 风控提示词清洗**（`Prompt Sanitizer`）可打开独立整页，提供总开关（`promptSanitizer`）、客户端身份归一化与去重（`normalize_identity`）、系统提示词隐身侧载（`sideload_mode`：`off` / `auto` / `always`，默认 `off` 以契合 `Antigravity2API` `SYSTEM_PROMPT=full` 的 `<USER_REQUEST>` 封装，支持三段式分段控件按需切换）、工具描述清洗（`sanitize_tools_description`）、自定义 / 12 条推荐预设改写规则的增删改排序与一键恢复预设；页面底部固定保存 / 还原栏，保存后热更新生效；读取设置失败时禁止保存并给出提示与「重试」按钮；同时兼容通过 Plugins → Options JSON 编辑。
  - **「拉取 Antigravity Tools 最新规则」（`Fetch latest Antigravity Tools rules`，在线）**：页面经 `magpie.page.service`（本机 `127.0.0.1:18417`，端口可由 `pageServicePort` 选项调整，修改端口后旧端口自动关闭，`disablePageService: true` 可停掉已在运行的服务）托管后，点击并经二次确认，通过 `GET api/upstream-presets` 拉取 Antigravity-Manager 仓库 `beta` 分支最新推荐规则（服务端缓存 60 秒；若遇到页面服务尚未唤醒的非 JSON 代理 `502` 或网络异常，自动唤醒 `./` 并轮询 `health` 就绪后重试），将 4 个开关复位为默认开启、`sideload_mode` 复位为 `off`；上游规则采用严格解析，只要存在任一无法识别的条目、总数超过 64 条、`id` 重复或字段超长，即整体报错且不改动当前草稿；拉取期间若草稿已被修改则不覆盖并给出提示，拉到的规则与已保存设置一致时提示无需保存；结果载入草稿后需点击「保存并生效」才会应用，也可点击「还原」撤销。未经服务代理（静态页面）访问时该按钮禁用。
  - **「恢复本地预设」（离线）**：无需联网，点击并经二次确认后，将 4 个开关全部开启、`sideload_mode` 复位为 `off` 并恢复内置 12 条推荐规则，可作为在线拉取失败时的兜底。
  - 静态页面加载后会通过 `magpie.service` 自动无缝跳转到服务托管页（`ui/service-bridge.js` 提供与 Magpie `pagebridge.js` 一致的 `postMessage` 桥）。

- **管理员会话认证 (`POST /api/session`)**：自动使用 `adminUsername` / `adminPassword` 登录换取 `antigravity_admin` Cookie（11 小时缓存、按凭据范围隔离进行中的登录与配额/模型缓存、并发登录合并、`401` 自动重登、刷新后仍 `401/403` 自动清理失效缓存、登录被拒后 60 秒内不重复尝试、登录 `429` `Retry-After` 退避防抖），同时支持本机免密访问；认证被拒时不回退展示旧账号明细。
- **全动态模型发现**：优先从管理接口 `GET /api/models` 与 `GET /api/settings` 读取完整模型元数据（`quota_group`、`thinking_levels`、`default_thinking_level`、上下文与输出上限、多模态能力与 `MODEL_MAPPING` 别名）；动态剔除 `transcription` / `completion` 非对话内部模型，为生图模型设置 `output: ["image"]` 并关闭 `toolcall`/`reasoning`，未给出上限时置 `0` 交由目录继承；不为 `MODEL_MAPPING` 自定义别名合成后缀模型，固定档位后缀模型锁定单档 `variants` 避免触发借用档位；管理接口成功返回空目录或公开接口合法返回空目录时均视为有效空结果清空旧模型，公开 API Key 被拒绝（`401`/`403`/Gemini `400 API_KEY_INVALID`）时标为凭据失效；缓存按认证范围隔离并支持 60s TTL 刷新。零写死模型白名单。
- **多协议自动分流与会话上下文适配**：目录条目带 `provider` 字段时以该字段为准选择协议，否则按模型名前缀分流（`claude-*` -> `@ai-sdk/anthropic`，`gemini-*`/`imagen-*` -> `@ai-sdk/google`，`gpt-*` -> `@ai-sdk/openai-compatible`）。出站前无条件剥离 `x-magpie-*` 与 `x-agy2api-cache-session` 内部头；仅当推理或 `countTokens` 请求缺少原生会话标识（且非 `responses.previous_response_id` 续接链或损坏 JSON Body）时，按 `x-magpie-session`（子代理搭配 `x-magpie-subagent` 派生隔离哈希）补写 `x-session-id`，确保主会话与子代理上游缓存分区准确隔离。
- **动态 `xhigh` 思考强度透传**：仅对 `thinking_levels` 包含 `xhigh` 的 Gemini 模型将 `X-Magpie-Effort: xhigh` 改写为 `generationConfig.thinkingConfig.thinkingLevel = "xhigh"`，同时删除冲突的 `thinkingBudget`（不强制设置 `includeThoughts`）。
- **全 4 协议缓存亲和思考档位对齐 (`preserve_cache_effort`)**：覆盖 `gemini`、`anthropic`、`chat`（`/v1/chat/completions`）与 `responses`（`/v1/responses`）四种协议；开关支持热更新，并将前缀指纹纳入工具定义与显式缓存引用，在条目标记淘汰或过期后仍通过递增序号阻止慢请求乱序回写；跳过单物理模型、固定档位后缀模型及物理档位未变的请求，显式关闭思考（含 `between_tools`、`configuration_update`）不参与对齐，并保留 `includeThoughts: false` 与结构化输出等兄弟字段；按 Magpie 会话（含子代理隔离）与 API Key 隔离状态。
- **精细化故障隔离规范化**：未命中任何规则的错误响应保持原始字节与响应头透传。
  - `401` / `400 API_KEY_INVALID`：区分上游 Google OAuth 失效（`X-Magpie-Sign-In: kept`，不误废有效 Key）与公开 API Key 无效（`X-Magpie-Sign-In: expired`）。
  - `404`：对模型推理与 `countTokens` 端点上的模型不存在错误注入完整 `requestedModel` 与 `error.model` 以便精准隔离单模型。
  - `429`：识别 `CooldownError`（`All accounts for model` / `No available accounts for model`）、明确额度耗尽（`QUOTA_EXHAUSTED`、`INSUFFICIENT_G1_CREDITS_BALANCE`）与 `upstream 429`，前置模型上下文并保留 `Retry-After`；无模型名的服务级不可用原样透传。
  - `502` / `400` 内容拒绝：针对 `Upstream stopped generation due to content policy:`（`502`）及 `400` 上游内容审查拒绝，补充 `content_policy_violation` / `invalid_prompt` 识别字段并保留原始诊断信息。
  - `503` / `529`：严格区分服务级不可用（原样透传）与模型级过载（精准隔离单模型）。
- **逐账号资格、共享周池去重与短板额度聚合**：
  - 支持 `ready` 与 `cooling` 状态账号，并结合 `/api/settings` 的 `API_KEY_ACCOUNTS`（受 `API_KEYS` 激活）、`QUOTA_RESERVE_PERCENT` 与并发读取的单账号 `/api/accounts/{id}/models` 目录过滤有资格账号；单个档位后缀冷却不会连坐屏蔽裸模型或其他档位，裸模型仅在全部物理档位均冷却时判定为冷却。
  - 配额池按可调度账号在 `GET /api/accounts` 中实际返回的额度桶动态发现；通过并查集对 `shared[池]` 与 `family`（已启动周桶 `< 1` 且 `reset_time` 相差 `<= 2s`）仅去重 `7d` 周池，严格保留逐账号独立 `5h` 窗口与 `min(5h, 7d)` 短板约束（同周池多账号取各未冷却成员可出站剩余的最大值，`5 hours` 汇总条不跨共享周池做 `min` 合并）。
  - 周额度为主导瓶颈时精准归因 `span = 604800` 与最早周重置时间；全池 `used: 100` 时按所有有资格账号的最早全部阻塞解除时间计算 `resetsAt`；账号仍有可用 AI 积分时将对应模型窗标为 `aside: true`。
  - 兼容刷新 `failed` 对象与数组格式；回退旧缓存时基于缓存抓取时刻判定桶是否过期，超过 60 秒的陈旧缓存统一标为 `aside: true` 仅作展示。

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
