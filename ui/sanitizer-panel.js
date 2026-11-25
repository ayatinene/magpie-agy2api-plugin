(function () {
  "use strict";

  /* ------------------------------------------------------------------ *
   * Constants (must stay in sync with lib/sanitizer.mjs / middleware.mjs)
   * ------------------------------------------------------------------ */
  var MAX_RULES = 64;
  var MAX_PATTERN_CHARS = 8192;
  var MAX_REPLACEMENT_CHARS = 16384;
  var SCOPES = ["all", "prompt", "tools"];
  var SIDELOAD_MODES = ["off", "auto", "always"];
  var AUX_POLICIES = ["keep", "current_low", "fallback_model"];
  var AUX_EFFORTS = ["minimal", "low", "medium", "high", "xhigh", "max"];
  // numeric aux_* thresholds: defaults mirror package.json magpie.options / lib/aux-router.mjs
  var AUX_NUM = [
    { key: "minBodyBytes", snake: "aux_min_body_bytes", camel: "auxMinBodyBytes", def: "32768", max: "6291456", input: "in-aux-min" },
    { key: "maxOutputTokens", snake: "aux_max_output_tokens", camel: "auxMaxOutputTokens", def: "8192", max: "1048576", input: "in-aux-out" },
    { key: "sessionTtlSec", snake: "aux_session_ttl_sec", camel: "auxSessionTtlSec", def: "600", max: "86400", input: "in-aux-ttl" }
  ];
  var AUX_KEYS = [
    "aux_incompatible_policy", "auxIncompatiblePolicy", "aux_fallback_model", "auxFallbackModel",
    "aux_fallback_effort", "auxFallbackEffort", "aux_min_body_bytes", "auxMinBodyBytes",
    "aux_max_output_tokens", "auxMaxOutputTokens", "aux_session_ttl_sec", "auxSessionTtlSec"
  ];

  var PRESETS = [
    { id: "preset-opencode", pattern: "You are an AI agent running in OpenCode*", replacement: "", scope: "prompt", enabled: true },
    { id: "preset-claude-code-agent", pattern: "You are an interactive agent that helps users with software engineering tasks*", replacement: "", scope: "prompt", enabled: true },
    { id: "preset-opencode-session-move", pattern: "*tools.opencode.session*move*", replacement: "tools.opencode.session_relocate", scope: "all", enabled: true },
    { id: "preset-dsh-identity", pattern: "You are an AI agent powered by DeepSeek Harness*", replacement: "", scope: "prompt", enabled: true },
    { id: "preset-dsh-model", pattern: "You are a coding agent powered by *gemini*", replacement: "", scope: "prompt", enabled: true },
    { id: "preset-dsh-browser-context", pattern: "*The browser provides no implicit DOM, route, or screenshot context*", replacement: "The browser exposes no DOM tree, route list, or page screenshot context", scope: "prompt", enabled: true },
    { id: "preset-workbuddy", pattern: "*WorkBuddy*", replacement: "", scope: "all", enabled: true },
    { id: "preset-workbuddy-powered-by", pattern: "*This conversation is powered by *", replacement: "Selected model: ", scope: "prompt", enabled: true },
    { id: "preset-codex-desktop-context", pattern: "*# Codex desktop context*", replacement: "# Desktop application context", scope: "prompt", enabled: true },
    { id: "preset-codex-as-role", pattern: "*as Codex:*", replacement: "as an assistant:", scope: "prompt", enabled: true },
    { id: "preset-codex-intro", pattern: "*the codex cli is an open*source project*", replacement: "", scope: "prompt", enabled: true },
    { id: "preset-anthropic-billing", pattern: "*x-anthropic-billing-header:*", replacement: "", scope: "prompt", enabled: true }
  ];

  var I18N = {
    zh: {
      "page.title": "Antigravity2API · 风控提示词清洗",
      "seg.off": "关",
      "seg.on": "开",
      "page.sub": "清洗发送到 Antigravity2API 的请求：剥离 WAF 触发请求头、归一化客户端身份、清理工具描述，并应用自定义改写规则。",
      "sec.sanitizer": "Antigravity2API · 风控提示词清洗",
      "master.title": "启用清洗中间件",
      "master.inactive": "清洗中间件已关闭，以下设置当前不会生效。",
      "identity.title": "客户端身份归一化与去重",
      "identity.desc": "将各类客户端的身份声明统一并去除重复段落。",
      "sideload.title": "系统提示词隐身侧载",
      "sideload.desc": "将客户端复杂系统提示词侧载至首轮用户消息的 <system-instruction> 中，出站仅保留纯净官方 Antigravity 系统提示词以规避 WAF 拦截。智能模式在超过 300 字节或含指令关键词时自动触发。",
      "sideload.off": "关闭",
      "sideload.auto": "智能",
      "sideload.always": "始终",
      "tools.title": "工具描述清洗",
      "tools.desc": "清理工具描述中可能触发拦截的内容。",
      "rewrite.title": "启用自定义 / 预设改写规则",
      "rewrite.desc": "关闭后下方所有改写规则均不会应用。",
      "rules.summary": "改写规则",
      "rules.note": "模式使用通配符语法：`*` 匹配同一行内的任意文本，`\\*` 表示字面星号，`\\n` / `\\t` 为换行 / 制表符转义；匹配不区分大小写，围栏代码块内的内容受保护，规则按顺序依次应用，最多 64 条。",
      "rules.add": "+ 添加规则",
      "rules.reset": "恢复本地预设",
      "rules.resetConfirm": "确认恢复本地预设？",
      "rules.resetTip": "离线可用：4 个开关全部开启、侧载模式复位为关闭，并恢复内置 12 条推荐规则",
      "rules.sync": "拉取 Antigravity Tools 最新规则",
      "rules.syncConfirm": "确认拉取并覆盖？",
      "rules.syncBusy": "正在拉取 Antigravity Tools 规则…",
      "rules.syncTip": "联网拉取 Antigravity Tools（beta 分支）最新推荐规则，替换当前规则，并复位 4 个默认开关与侧载模式（默认关闭）",
      "rules.syncUnavailable": "需通过 Magpie 服务代理访问以联网拉取",
      "rules.limit": "已启用 {x}/{y} · 上限 {max}",
      "rules.empty": "暂无规则。可点击“添加规则”或恢复预设。",
      "rules.maxReached": "已达到 64 条上限",
      "rule.enable": "启用此规则",
      "rule.scope": "作用范围",
      "scope.all": "全部",
      "scope.prompt": "提示词",
      "scope.tools": "工具描述",
      "hint.all": "匹配提示词与工具描述",
      "hint.prompt": "仅匹配提示词",
      "hint.tools": "仅匹配工具描述",
      "rule.pattern": "匹配模式",
      "rule.patternPh": "例如：*关键词*",
      "rule.replacement": "替换为",
      "rule.replacementPh": "留空则删除匹配内容",
      "rule.up": "上移",
      "rule.down": "下移",
      "rule.delete": "删除",
      "warn.empty": "模式为空，该规则将被跳过",
      "warn.wildcard": "模式可匹配空文本（如 * 或 ***），该规则将被跳过",
      "warn.patternLong": "模式超过 8192 个字符，该规则将被跳过",
      "warn.replacementLong": "替换内容超过 16384 个字符，该规则将被跳过",
      "foot.dirty": "未保存",
      "foot.save": "保存并生效",
      "foot.saving": "保存中…",
      "foot.revert": "还原",
      "foot.saved": "已保存，下一条请求生效",
      "foot.reverted": "已还原为上次保存的设置",
      "foot.rateLimited": "保存过于频繁，请稍后再试",
      "foot.failed": "保存失败，请重试",
      "foot.loadFailed": "读取设置失败，当前显示默认值，暂时无法保存",
      "foot.retry": "重试",
      "foot.retryFailed": "重试失败，请稍后再试",
      "foot.reloaded": "已读取设置",
      "foot.reloadedDiscard": "已读取设置，读取失败期间的修改已丢弃",
      "sync.ok": "已拉取 Antigravity Tools 最新规则（{n} 条）并复位默认开关，请点击「保存并生效」",
      "sync.same": "已是 Antigravity Tools 最新规则（{n} 条），与已保存的设置一致，无需保存",
      "sync.stale": "拉取期间设置有改动，已保留你的修改，未应用拉取结果",
      "sync.fail": "拉取 Antigravity Tools 规则失败：{err}（可点击「恢复本地预设」）",
      "sync.unknownErr": "未知错误",
      "sec.aux": "辅助请求路由",
      "aux.defaults": "恢复默认",
      "aux.defaultsConfirm": "确认恢复默认？",
      "aux.defaultsTip": "仅将「辅助请求路由」恢复为默认值，不影响清洗设置与改写规则",
      "aux.off.title": "缓存亲和总开关已关闭，辅助请求路由当前不生效",
      "aux.off.provider": "来自 Provider 弹窗中的「preserve_cache_effort」开关，请在 Provider 设置中重新开启。",
      "aux.off.plugin": "来自插件选项（plugins.json）中的 preserve_cache_effort，请在 Plugins → Options 中修改。",
      "aux.off.static": "来自插件内置的静态默认配置，当前未被 Provider 托管。",
      "aux.policy.title": "不兼容辅助请求策略",
      "aux.policy.desc": "前缀与主会话缓存不兼容的辅助请求（如记忆提取、标题生成）的处理方式。",
      "aux.policy.keep": "保持原样",
      "aux.policy.current_low": "当前 Low",
      "aux.policy.fallback_model": "回退模型",
      "aux.model.title": "回退模型",
      "aux.model.desc": "策略为「回退模型」时，将辅助请求切换到的低成本模型，候选来自当前动态模型目录。",
      "aux.model.choose": "选择模型…",
      "aux.model.notFound": "{id}（当前目录未发现）",
      "aux.model.unset": "尚未选择回退模型，运行时将按「当前 Low」处理。",
      "aux.model.missing": "已保存的模型不在当前目录中，运行时将按「当前 Low」处理。",
      "aux.model.empty": "当前模型目录为空，暂无可选模型。",
      "aux.model.loadFailed": "模型目录读取失败：{err}",
      "aux.model.ambiguous": "检测到多个登录作用域，无法确定模型目录，运行时将按「当前 Low」处理。",
      "aux.model.refresh": "刷新模型目录",
      "aux.refreshFailed": "刷新模型目录失败：{err}",
      "aux.effort.title": "回退思考档位",
      "aux.effort.desc": "回退模型使用的思考档位，仅列出所选模型支持的档位。",
      "aux.effort.fixed": "档位由模型别名固定：{effort}",
      "aux.effort.none": "无思考参数 · 自动剥离",
      "aux.effort.default": "默认",
      "aux.effort.switched": "所选模型不支持 {from}，已切换为 {to}",
      "aux.effort.adapt": "已保存的档位 {from} 不被所选模型支持，运行时将自动适配为 {to}",
      "aux.effort.auto": "未选定模型或模型不在当前目录中，运行时将按目标模型自动适配档位。",
      "effort.minimal": "Minimal",
      "effort.low": "Low",
      "effort.medium": "Medium",
      "effort.high": "High",
      "effort.xhigh": "XHigh",
      "effort.max": "Max",
      "aux.adv.title": "高级参数",
      "aux.adv.default": "默认",
      "aux.adv.changed": "已修改 {n} 项",
      "aux.minBody.title": "最小请求体",
      "aux.minBody.desc": "结构启发式判定辅助请求的最小请求体字节数，低于该体积不触发。",
      "aux.maxOut.title": "最大输出 Token",
      "aux.maxOut.desc": "结构启发式判定辅助请求的最大输出 Token 上限。",
      "aux.ttl.title": "会话缓存存活",
      "aux.ttl.desc": "主会话热缓存与前缀快照的存活时间。",
      "aux.unit.bytes": "字节",
      "aux.unit.tokens": "Token",
      "aux.unit.sec": "秒",
      "aux.num.placeholder": "默认 {def}",
      "aux.num.invalid": "请输入 0 到 {max} 的整数",
      "aux.invalidFooter": "有 {n} 项数值无效，修正后才能保存"
    },
    en: {
      "page.title": "Antigravity2API \u00b7 Prompt Sanitizer",
      "seg.off": "Off",
      "seg.on": "On",
      "page.sub": "Sanitizes requests sent to Antigravity2API: strips WAF-triggering headers, normalizes client identity, cleans tool descriptions, and applies your custom rewrite rules.",
      "sec.sanitizer": "Antigravity2API · Prompt sanitizer",
      "master.title": "Sanitize requests",
      "master.inactive": "The sanitizer is off. The settings below are inactive.",
      "identity.title": "Normalize & dedupe client identity",
      "identity.desc": "Unifies client identity statements and removes duplicate blocks.",
      "sideload.title": "Stealth system prompt sideload",
      "sideload.desc": "Moves complex client system prompts into a <system-instruction> block in the first user turn so Antigravity2API sends a pure official Antigravity system prompt upstream. Auto triggers over 300 bytes or on instruction keywords.",
      "sideload.off": "Off",
      "sideload.auto": "Auto",
      "sideload.always": "Always",
      "tools.title": "Sanitize tool descriptions",
      "tools.desc": "Cleans tool descriptions of content that may trigger blocking.",
      "rewrite.title": "Enable custom & preset rewrite rules",
      "rewrite.desc": "When off, none of the rewrite rules below are applied.",
      "rules.summary": "Rewrite rules",
      "rules.note": "Patterns use glob syntax: `*` matches text on the same line, `\\*` is a literal asterisk, `\\n` / `\\t` are escapes. Matching is case-insensitive, fenced code blocks are protected, rules apply in order, max 64 rules.",
      "rules.add": "+ Add rule",
      "rules.reset": "Restore built-in",
      "rules.resetConfirm": "Confirm built-in reset?",
      "rules.resetTip": "Works offline: turns all 4 switches on, resets sideload to Off, and restores the bundled 12 preset rules",
      "rules.sync": "Fetch latest Antigravity Tools rules",
      "rules.syncConfirm": "Confirm fetch and overwrite?",
      "rules.syncBusy": "Fetching Antigravity Tools rules…",
      "rules.syncTip": "Fetch the latest recommended Antigravity Tools rules (beta branch) online, replace the current rules, and reset the 4 default switches and sideload mode (Off)",
      "rules.syncUnavailable": "Requires Magpie page service to fetch upstream",
      "rules.limit": "{x}/{y} enabled · limit {max}",
      "rules.empty": "No rules yet. Add one or reset to the recommended presets.",
      "rules.maxReached": "Reached the 64 rule limit",
      "rule.enable": "Enable this rule",
      "rule.scope": "Scope",
      "scope.all": "All",
      "scope.prompt": "Prompt",
      "scope.tools": "Tools",
      "hint.all": "Matches prompts and tool descriptions",
      "hint.prompt": "Matches prompts only",
      "hint.tools": "Matches tool descriptions only",
      "rule.pattern": "Pattern",
      "rule.patternPh": "e.g. *keyword*",
      "rule.replacement": "Replacement",
      "rule.replacementPh": "Leave empty to strip match",
      "rule.up": "Move up",
      "rule.down": "Move down",
      "rule.delete": "Delete",
      "warn.empty": "Pattern is empty; this rule will be skipped",
      "warn.wildcard": "Pattern can match empty text (e.g. * or ***); this rule will be skipped",
      "warn.patternLong": "Pattern exceeds 8192 characters; this rule will be skipped",
      "warn.replacementLong": "Replacement exceeds 16384 characters; this rule will be skipped",
      "foot.dirty": "Unsaved changes",
      "foot.save": "Save",
      "foot.saving": "Saving...",
      "foot.revert": "Revert",
      "foot.saved": "Saved \u00b7 applies on next request",
      "foot.reverted": "Reverted to last saved settings",
      "foot.rateLimited": "Saving too fast, please retry shortly",
      "foot.failed": "Save failed, please retry",
      "foot.loadFailed": "Could not read settings. Showing defaults; saving is disabled.",
      "foot.retry": "Retry",
      "foot.retryFailed": "Retry failed. Please try again shortly.",
      "foot.reloaded": "Settings loaded",
      "foot.reloadedDiscard": "Settings loaded. Edits made before they could be read were discarded.",
      "sync.ok": "Loaded {n} latest Antigravity Tools rules and reset the default switches. Click Save to apply.",
      "sync.same": "Already matches the latest Antigravity Tools rules ({n} rules). Nothing to save.",
      "sync.stale": "Settings changed while fetching. Your edits were kept and the fetched rules were not applied.",
      "sync.fail": "Failed to fetch Antigravity Tools rules: {err} (you can use \"Restore built-in\")",
      "sync.unknownErr": "Unknown error",
      "sec.aux": "Auxiliary request routing",
      "aux.defaults": "Restore defaults",
      "aux.defaultsConfirm": "Confirm restore?",
      "aux.defaultsTip": "Restores only Auxiliary request routing to its defaults. Sanitizer switches and rewrite rules are untouched.",
      "aux.off.title": "Cache-affinity master switch is off. Auxiliary routing is inactive.",
      "aux.off.provider": "Set by the preserve_cache_effort switch in the Provider dialog. Turn it back on in Provider settings.",
      "aux.off.plugin": "Set by preserve_cache_effort in the plugin options (plugins.json). Change it under Plugins → Options.",
      "aux.off.static": "Comes from the plugin's built-in static defaults and is not managed by a Provider.",
      "aux.policy.title": "Incompatible auxiliary policy",
      "aux.policy.desc": "How auxiliary requests (e.g. memory extraction, titles) whose prefix is incompatible with the main session cache are handled.",
      "aux.policy.keep": "Keep",
      "aux.policy.current_low": "Current Low",
      "aux.policy.fallback_model": "Fallback",
      "aux.model.title": "Fallback model",
      "aux.model.desc": "Low-cost model that auxiliary requests are switched to when the policy is Fallback. Candidates come from the live model catalog.",
      "aux.model.choose": "Choose a model…",
      "aux.model.notFound": "{id} (not in current catalog)",
      "aux.model.unset": "No fallback model chosen yet. Requests are handled as Current Low at runtime.",
      "aux.model.missing": "The saved model is not in the current catalog. Requests are handled as Current Low at runtime.",
      "aux.model.empty": "The model catalog is empty, so no models are available to choose.",
      "aux.model.loadFailed": "Could not load the model catalog: {err}",
      "aux.model.ambiguous": "Multiple login scopes detected, so the model catalog cannot be determined. Requests are handled as Current Low at runtime.",
      "aux.model.refresh": "Refresh model catalog",
      "aux.refreshFailed": "Could not refresh the model catalog: {err}",
      "aux.effort.title": "Fallback effort",
      "aux.effort.desc": "Reasoning effort used with the fallback model. Only levels supported by the chosen model are listed.",
      "aux.effort.fixed": "Effort is fixed by the model alias: {effort}",
      "aux.effort.none": "No reasoning · stripped automatically",
      "aux.effort.default": "default",
      "aux.effort.switched": "The selected model does not support {from}; switched to {to}",
      "aux.effort.adapt": "Saved effort {from} is not supported by the selected model; it will be adapted to {to} at runtime",
      "aux.effort.auto": "No model chosen, or it is not in the current catalog. The effort is adapted to the target model at runtime.",
      "effort.minimal": "Minimal",
      "effort.low": "Low",
      "effort.medium": "Medium",
      "effort.high": "High",
      "effort.xhigh": "XHigh",
      "effort.max": "Max",
      "aux.adv.title": "Advanced",
      "aux.adv.default": "Default",
      "aux.adv.changed": "{n} changed",
      "aux.minBody.title": "Minimum body size",
      "aux.minBody.desc": "Minimum request body size for the structural heuristic to treat a request as auxiliary. Smaller bodies are ignored.",
      "aux.maxOut.title": "Max output tokens",
      "aux.maxOut.desc": "Maximum output token cap for the structural heuristic to treat a request as auxiliary.",
      "aux.ttl.title": "Session cache lifetime",
      "aux.ttl.desc": "How long the main-session hot cache and prefix snapshots are kept.",
      "aux.unit.bytes": "bytes",
      "aux.unit.tokens": "tokens",
      "aux.unit.sec": "s",
      "aux.num.placeholder": "Default {def}",
      "aux.num.invalid": "Enter an integer from 0 to {max}",
      "aux.invalidFooter": "{n} invalid value(s). Fix them to save."
    }
  };

  /* ------------------------------------------------------------------ *
   * State
   * ------------------------------------------------------------------ */
  var lang = "zh";
  var baseOptions = {};   // last loaded / saved plugin options (all keys)
  var saved = null;       // normalized snapshot of baseOptions
  var draft = null;       // normalized working copy
  var expanded = true;
  var saving = false;
  var resetArmed = false;
  var resetTimer = 0;
  var statusKey = "";
  var statusKind = "";
  var statusVars = null;
  var statusTimer = 0;
  var syncing = false;
  var syncArmed = false;
  var syncTimer = 0;
  var loadError = false;  // options.get() failed: defaults are shown, saving stays disabled
  var loadingOpts = false;
  var idSeq = 0;
  var els = {};

  // Live aux-routing catalog / master switch (GET api/aux-routing/state). Never part of draft or dirty.
  var auxState = { loaded: false, preserveCacheEffort: true, preserveSource: "default", catalogStatus: "ok", catalogError: "", models: [] };
  var auxSeq = 0;           // latest request wins
  var auxRefreshing = false;
  var auxEffortNote = null; // { key, vars } set only by a user-driven model switch
  var auxArmed = false;
  var auxTimer = 0;
  var auxAdvOpen = false;

  /* ------------------------------------------------------------------ *
   * Helpers
   * ------------------------------------------------------------------ */
  function t(key, vars) {
    var table = I18N[lang] || I18N.zh;
    var s = table[key];
    if (s === undefined) s = I18N.en[key];
    if (s === undefined) s = key;
    if (vars) {
      s = s.replace(/\{(\w+)\}/g, function (m, k) {
        return vars[k] === undefined ? m : String(vars[k]);
      });
    }
    return s;
  }

  function $(id) { return document.getElementById(id); }

  function isObj(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }

  function coerceBool(v, fallback) {
    if (typeof v === "boolean") return v;
    if (typeof v === "string") {
      var s = v.trim().toLowerCase();
      if (s === "false" || s === "0" || s === "off" || s === "no") return false;
      if (s === "true" || s === "1" || s === "on" || s === "yes") return true;
    }
    return fallback;
  }

  function pick(obj, a, b) {
    if (obj[a] !== undefined && obj[a] !== null) return obj[a];
    return obj[b];
  }

  /* aux_* readers mirror lib/aux-router.mjs readOptionValue: snake_case first, then camelCase,
     each only winning when it coerces to a valid value. */
  function pickCoerced(o, snake, camel, coerce, fallback) {
    if (Object.prototype.hasOwnProperty.call(o, snake)) {
      var a = coerce(o[snake]);
      if (a !== undefined) return a;
    }
    if (Object.prototype.hasOwnProperty.call(o, camel)) {
      var b = coerce(o[camel]);
      if (b !== undefined) return b;
    }
    return fallback;
  }

  function coercePolicy(v) {
    if (typeof v !== "string") return undefined;
    var s = v.trim().toLowerCase();
    return AUX_POLICIES.indexOf(s) >= 0 ? s : undefined;
  }

  function coerceEffort(v) {
    if (typeof v !== "string") return undefined;
    var s = v.trim().toLowerCase().replace(/^thinking_level_/, "");
    return AUX_EFFORTS.indexOf(s) >= 0 ? s : undefined;
  }

  function coerceModelId(v) { return typeof v === "string" ? v.trim() : undefined; }

  function stripZeros(s) { return s.replace(/^0+(?=\d)/, ""); }

  /** Matches lib/aux-router.mjs tryCoerceNonNegNum so CLI values like "1e3" or 1.5 load losslessly. */
  function coerceNonNegNum(v) {
    if (typeof v === "number") return Number.isFinite(v) && v >= 0 ? String(v) : undefined;
    if (typeof v === "string" && v.trim()) {
      var n = Number(v);
      return Number.isFinite(n) && n >= 0 ? String(n) : undefined;
    }
    return undefined;
  }

  function defaultAux() {
    return {
      policy: "current_low",
      fallbackModel: "",
      fallbackEffort: "low",
      minBodyBytes: AUX_NUM[0].def,
      maxOutputTokens: AUX_NUM[1].def,
      sessionTtlSec: AUX_NUM[2].def
    };
  }

  function normAux(o) {
    var a = defaultAux();
    a.policy = pickCoerced(o, "aux_incompatible_policy", "auxIncompatiblePolicy", coercePolicy, a.policy);
    a.fallbackModel = pickCoerced(o, "aux_fallback_model", "auxFallbackModel", coerceModelId, a.fallbackModel);
    a.fallbackEffort = pickCoerced(o, "aux_fallback_effort", "auxFallbackEffort", coerceEffort, a.fallbackEffort);
    for (var i = 0; i < AUX_NUM.length; i++) {
      var d = AUX_NUM[i];
      a[d.key] = pickCoerced(o, d.snake, d.camel, coerceNonNegNum, d.def);
    }
    return a;
  }

  /** Numeric aux field is valid when empty (= default), an untouched valid CLI number, or digits-only <= max. */
  function auxNumValid(d, value) {
    var v = String(value).trim();
    if (v === "") return true;
    if (saved && saved.aux && v === saved.aux[d.key] && coerceNonNegNum(v) !== undefined) return true;
    if (!/^\d+$/.test(v)) return false;
    v = stripZeros(v);
    if (v.length !== d.max.length) return v.length < d.max.length;
    return v <= d.max;
  }

  function auxNumCanon(d, value) {
    var v = String(value).trim();
    if (v === "") return d.def;
    if (/^\d+$/.test(v)) return stripZeros(v);
    var c = coerceNonNegNum(v);
    return c !== undefined ? c : String(value);
  }

  function auxInvalidCount() {
    var n = 0;
    if (!draft) return 0;
    for (var i = 0; i < AUX_NUM.length; i++) if (!auxNumValid(AUX_NUM[i], draft.aux[AUX_NUM[i].key])) n++;
    return n;
  }

  function auxChangedCount() {
    var n = 0;
    for (var i = 0; i < AUX_NUM.length; i++) {
      var d = AUX_NUM[i];
      var v = draft.aux[d.key];
      if (!auxNumValid(d, v) || auxNumCanon(d, v) !== d.def) n++;
    }
    return n;
  }

  function normScope(s) {
    if (typeof s !== "string") return "all";
    var v = s.trim().toLowerCase();
    return SCOPES.indexOf(v) >= 0 ? v : "all";
  }

  function normSideload(v) {
    if (typeof v !== "string") return "off";
    var s = v.trim().toLowerCase();
    return SIDELOAD_MODES.indexOf(s) >= 0 ? s : "off";
  }

  function cloneRule(r) {
    return { id: r.id, pattern: r.pattern, replacement: r.replacement, scope: r.scope, enabled: r.enabled };
  }

  function presetRules() { return PRESETS.map(cloneRule); }

  function newId() {
    idSeq += 1;
    return "custom-" + Date.now().toString(36) + "-" + idSeq;
  }

  function normRule(r) {
    var id = typeof r.id === "string" && r.id ? r.id : newId();
    return {
      id: id,
      pattern: typeof r.pattern === "string" ? r.pattern : "",
      replacement: typeof r.replacement === "string" ? r.replacement : "",
      scope: normScope(r.scope),
      enabled: coerceBool(r.enabled, true)
    };
  }

  /** Build a normalized {promptSanitizer, promptRewrite} view from raw options. */
  function normalize(opts) {
    var o = isObj(opts) ? opts : {};
    var rawRw = pick(o, "promptRewrite", "prompt_rewrite");
    var rw = isObj(rawRw) ? rawRw : {};
    var rules;
    if (Array.isArray(rw.rules)) {
      rules = [];
      for (var i = 0; i < rw.rules.length && rules.length < MAX_RULES; i++) {
        if (isObj(rw.rules[i])) rules.push(normRule(rw.rules[i]));
      }
    } else {
      rules = presetRules();
    }
    return {
      promptSanitizer: coerceBool(pick(o, "promptSanitizer", "prompt_sanitizer"), true),
      promptRewrite: {
        enabled: coerceBool(rw.enabled, true),
        normalize_identity: coerceBool(pick(rw, "normalize_identity", "normalizeIdentity"), true),
        sideload_mode: normSideload(pick(rw, "sideload_mode", "sideloadMode")),
        sanitize_tools_description: coerceBool(pick(rw, "sanitize_tools_description", "sanitizeToolsDescription"), true),
        rules: rules
      },
      aux: normAux(o)
    };
  }

  function cloneState(s) {
    return {
      promptSanitizer: s.promptSanitizer,
      promptRewrite: {
        enabled: s.promptRewrite.enabled,
        normalize_identity: s.promptRewrite.normalize_identity,
        sideload_mode: s.promptRewrite.sideload_mode,
        sanitize_tools_description: s.promptRewrite.sanitize_tools_description,
        rules: s.promptRewrite.rules.map(cloneRule)
      },
      aux: {
        policy: s.aux.policy,
        fallbackModel: s.aux.fallbackModel,
        fallbackEffort: s.aux.fallbackEffort,
        minBodyBytes: s.aux.minBodyBytes,
        maxOutputTokens: s.aux.maxOutputTokens,
        sessionTtlSec: s.aux.sessionTtlSec
      }
    };
  }

  /** Dirty key: an empty numeric aux field is the same as its default. */
  function stateKey(s) {
    var c = cloneState(s);
    for (var i = 0; i < AUX_NUM.length; i++) c.aux[AUX_NUM[i].key] = auxNumCanon(AUX_NUM[i], c.aux[AUX_NUM[i].key]);
    c.aux.fallbackModel = c.aux.fallbackModel.trim();
    return JSON.stringify(c);
  }

  function isDirty() { return stateKey(draft) !== stateKey(saved); }

  function cpLen(str) {
    var n = 0;
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        var d = str.charCodeAt(i + 1);
        if (d >= 0xdc00 && d <= 0xdfff) i++;
      }
      n++;
    }
    return n;
  }

  /** Mirrors compilePromptRewriteRules skip conditions. Returns i18n key or "". */
  function ruleWarning(rule) {
    var p = rule.pattern;
    if (!p) return "warn.empty";
    if (cpLen(p) > MAX_PATTERN_CHARS) return "warn.patternLong";
    if (cpLen(rule.replacement) > MAX_REPLACEMENT_CHARS) return "warn.replacementLong";
    // Matches empty text only if it is made purely of unescaped wildcards.
    if (/^\*+$/.test(p)) return "warn.wildcard";
    return "";
  }

  function langFrom(v) {
    return typeof v === "string" && /^zh/i.test(v) ? "zh" : "en";
  }

  function buildSaveObject() {
    var out = {};
    var keys = Object.keys(baseOptions);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      // legacy aliases are normalized into the canonical keys below
      if (k === "prompt_sanitizer" || k === "prompt_rewrite") continue;
      // aux_* keys (snake + camel) are rewritten below as the single canonical camelCase set
      if (AUX_KEYS.indexOf(k) >= 0) continue;
      out[k] = baseOptions[k];
    }
    out.promptSanitizer = draft.promptSanitizer;
    var prevRw = isObj(baseOptions.promptRewrite) ? baseOptions.promptRewrite
      : (isObj(baseOptions.prompt_rewrite) ? baseOptions.prompt_rewrite : {});
    var rw = {};
    var pk = Object.keys(prevRw);
    for (var j = 0; j < pk.length; j++) {
      var key = pk[j];
      if (key === "normalizeIdentity" || key === "sanitizeToolsDescription" || key === "sideloadMode") continue;
      rw[key] = prevRw[key];
    }
    rw.enabled = draft.promptRewrite.enabled;
    rw.normalize_identity = draft.promptRewrite.normalize_identity;
    rw.sideload_mode = draft.promptRewrite.sideload_mode;
    rw.sanitize_tools_description = draft.promptRewrite.sanitize_tools_description;
    rw.rules = draft.promptRewrite.rules.map(cloneRule);
    out.promptRewrite = rw;
    out.auxIncompatiblePolicy = draft.aux.policy;
    out.auxFallbackModel = draft.aux.fallbackModel.trim();
    out.auxFallbackEffort = draft.aux.fallbackEffort;
    out.auxMinBodyBytes = Number(auxNumCanon(AUX_NUM[0], draft.aux.minBodyBytes));
    out.auxMaxOutputTokens = Number(auxNumCanon(AUX_NUM[1], draft.aux.maxOutputTokens));
    out.auxSessionTtlSec = Number(auxNumCanon(AUX_NUM[2], draft.aux.sessionTtlSec));
    return out;
  }

  /* ------------------------------------------------------------------ *
   * Rendering
   * ------------------------------------------------------------------ */
  /** Magpie .segs control: reflect state on options + data-on, then place the thumb. */
  function setSwitch(seg, on) {
    on = !!on;
    seg.setAttribute("data-on", on ? "true" : "false");
    var opts = seg.querySelectorAll(".opt");
    for (var i = 0; i < opts.length; i++) {
      var isOn = (opts[i].getAttribute("data-val") === "on") === on;
      opts[i].classList.toggle("on", isOn);
      opts[i].setAttribute("aria-checked", isOn ? "true" : "false");
      opts[i].tabIndex = isOn ? 0 : -1;
    }
    syncThumb(seg);
  }

  /** Magpie .segs 3-option control keyed by data-val (off | auto | always). */
  function setSegValue(seg, val) {
    seg.setAttribute("data-val", val);
    var opts = seg.querySelectorAll(".opt");
    for (var i = 0; i < opts.length; i++) {
      var isOn = opts[i].getAttribute("data-val") === val;
      opts[i].classList.toggle("on", isOn);
      opts[i].setAttribute("aria-checked", isOn ? "true" : "false");
      opts[i].tabIndex = isOn ? 0 : -1;
    }
    syncThumb(seg);
  }

  /** Position the thumb under the active option (offsetLeft/offsetWidth). */
  function syncThumb(seg) {
    var thumb = seg.querySelector(".thumb");
    var opt = seg.querySelector(".opt.on");
    if (!thumb || !opt || !opt.offsetWidth) return false;   // not laid out yet: CSS fallback paints
    thumb.style.width = opt.offsetWidth + "px";
    thumb.style.transform = "translateX(" + opt.offsetLeft + "px)";
    if (!seg.classList.contains("measured")) {
      seg.classList.add("measured");
      // enable the slide transition only after the first placement has painted
      var enable = function () { seg.classList.add("ready"); };
      if (typeof window.requestAnimationFrame === "function") {
        window.requestAnimationFrame(function () { window.requestAnimationFrame(enable); });
      } else enable();
    }
    return true;
  }

  function syncAllSegs() {
    var segs = document.querySelectorAll(".segs");
    for (var i = 0; i < segs.length; i++) syncThumb(segs[i]);
  }

  function buildSegs() {
    var seg = mk("div", "segs");
    seg.setAttribute("role", "radiogroup");
    seg.appendChild(mk("span", "thumb"));
    seg.lastChild.setAttribute("aria-hidden", "true");
    var vals = ["off", "on"];
    for (var i = 0; i < 2; i++) {
      var b = mk("button", "opt", t("seg." + vals[i]));
      b.type = "button";
      b.setAttribute("role", "radio");
      b.setAttribute("data-val", vals[i]);
      b.setAttribute("data-i18n", "seg." + vals[i]);
      seg.appendChild(b);
    }
    return seg;
  }

  /** Arrow / Home / End keys move across all options like a native radio group. */
  function segKey(ev) {
    var opt = ev.target && ev.target.closest ? ev.target.closest(".opt") : null;
    if (!opt) return;
    var seg = opt.parentNode;
    var opts = seg.querySelectorAll(".opt");
    if (!opts.length) return;
    var cur = 0;
    for (var i = 0; i < opts.length; i++) if (opts[i] === opt) cur = i;
    var k = ev.key, to = -1;
    if (k === "ArrowLeft" || k === "ArrowUp") to = Math.max(0, cur - 1);
    else if (k === "ArrowRight" || k === "ArrowDown") to = Math.min(opts.length - 1, cur + 1);
    else if (k === "Home") to = 0;
    else if (k === "End") to = opts.length - 1;
    if (to < 0) return;
    ev.preventDefault();
    var next = opts[to];
    if (next) { next.focus(); next.click(); }
  }

  function setStatus(key, kind, autoClear, vars) {
    statusKey = key || "";
    statusKind = kind || "";
    statusVars = vars || null;
    if (statusTimer) { clearTimeout(statusTimer); statusTimer = 0; }
    renderFooter();
    if (key && autoClear) {
      statusTimer = setTimeout(function () {
        statusKey = ""; statusKind = ""; statusVars = null; statusTimer = 0;
        renderFooter();
      }, key === "sync.fail" ? 12000 : 6000);
    }
  }

  function renderStatic() {
    var nodes = document.querySelectorAll("[data-i18n]");
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].textContent = t(nodes[i].getAttribute("data-i18n"));
    }
    var titled = document.querySelectorAll("[data-i18n-title]");
    for (var j = 0; j < titled.length; j++) {
      titled[j].title = t(titled[j].getAttribute("data-i18n-title"));
    }
    document.documentElement.lang = lang;
    document.title = t("page.title");
    renderNote();
    els.add.textContent = t("rules.add");
    renderSync();
    els.save.textContent = saving ? t("foot.saving") : t("foot.save");
    els.revert.textContent = t("foot.revert");
    els.retry.textContent = t("foot.retry");
    els.dirty.textContent = t("foot.dirty");
  }

  function renderToggles() {
    var s = draft;
    setSwitch(els.swMaster, s.promptSanitizer);
    setSwitch(els.swIdentity, s.promptRewrite.normalize_identity);
    setSegValue(els.swSideload, s.promptRewrite.sideload_mode);
    setSwitch(els.swTools, s.promptRewrite.sanitize_tools_description);
    setSwitch(els.swRewrite, s.promptRewrite.enabled);
    els.subs.classList.toggle("inactive", !s.promptSanitizer);
    els.rulesBody.classList.toggle("inactive", !s.promptSanitizer || !s.promptRewrite.enabled);
    els.inactiveNote.hidden = s.promptSanitizer;
  }

  /** Foot note: `...` spans become real <code> nodes (no innerHTML). */
  function renderNote() {
    var parts = t("rules.note").split("`");
    var note = els.note;
    while (note.firstChild) note.removeChild(note.firstChild);
    for (var i = 0; i < parts.length; i++) {
      if (!parts[i]) continue;
      if (i % 2 === 1) note.appendChild(mk("code", "", parts[i]));
      else note.appendChild(document.createTextNode(parts[i]));
    }
  }

  function renderSummary() {
    var rules = draft.promptRewrite.rules;
    var enabled = 0;
    for (var i = 0; i < rules.length; i++) if (rules[i].enabled) enabled++;
    els.summary.textContent = t("rules.summary");
    els.limit.textContent = t("rules.limit", { x: enabled, y: rules.length, max: MAX_RULES });
    els.add.disabled = rules.length >= MAX_RULES;
    els.add.title = rules.length >= MAX_RULES ? t("rules.maxReached") : "";
    els.reset.textContent = resetArmed ? t("rules.resetConfirm") : t("rules.reset");
    els.reset.title = t("rules.resetTip");
    renderSync();
    els.reset.classList.toggle("armed", resetArmed);
    els.toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
    els.rulesBody.hidden = !expanded;
  }

  function renderSync() {
    var hosted = window.__magpieServiceHosted === true;
    els.sync.textContent = syncing ? t("rules.syncBusy") : (syncArmed ? t("rules.syncConfirm") : t("rules.sync"));
    els.sync.classList.toggle("armed", syncArmed);
    els.sync.disabled = !hosted || syncing || loadError;
    els.sync.title = hosted ? t("rules.syncTip") : t("rules.syncUnavailable");
    els.sync.setAttribute("aria-busy", syncing ? "true" : "false");
    els.reset.disabled = syncing;
  }

  function renderFooter() {
    var dirty = isDirty();
    var auxBad = auxInvalidCount();
    els.dirty.hidden = !dirty;
    els.save.textContent = saving ? t("foot.saving") : t("foot.save");
    els.revert.disabled = !dirty || saving;
    els.save.disabled = !dirty || saving || syncing || loadError || auxBad > 0;
    // a failed settings read stays visible until it succeeds; transient messages take precedence
    var key = statusKey || (loadError ? "foot.loadFailed" : (auxBad ? "aux.invalidFooter" : ""));
    var kind = statusKey ? statusKind : (loadError ? "err" : (auxBad ? "warn" : ""));
    var vars = statusKey ? statusVars : (auxBad ? { n: auxBad } : null);
    els.status.textContent = key ? t(key, vars) : "";
    els.status.className = "status" + (kind ? " " + kind : "");
    els.retry.hidden = !loadError;
    els.retry.disabled = loadingOpts;
    els.retry.setAttribute("aria-busy", loadingOpts ? "true" : "false");
  }

  function mk(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  var SVG_NS = "http://www.w3.org/2000/svg";

  function svgEl(tag, attrs) {
    var e = document.createElementNS(SVG_NS, tag);
    for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]);
    return e;
  }

  function svgIcon(cls, size, pathD, stroke) {
    var svg = svgEl("svg", { "class": cls, viewBox: "0 0 16 16", width: String(size), height: String(size), "aria-hidden": "true", focusable: "false" });
    var attrs = { d: pathD, fill: "none", stroke: "currentColor", "stroke-width": stroke, "stroke-linecap": "round", "stroke-linejoin": "round" };
    svg.appendChild(svgEl("path", attrs));
    return svg;
  }

  function iconBtn(cls, glyph, labelKey, disabled, action, idx) {
    var b = mk("button", "text ib " + cls);
    if (glyph && glyph.charAt(0) === "M") b.appendChild(svgIcon("", 12, glyph, "1.6"));
    else b.textContent = glyph;
    b.type = "button";
    b.disabled = !!disabled;
    var label = t(labelKey);
    b.setAttribute("aria-label", label);
    b.title = label;
    b.setAttribute("data-action", action);
    b.setAttribute("data-idx", String(idx));
    return b;
  }

  function buildInput(cls, field, value, labelKey, placeholderKey, idx) {
    var input = mk("input", "words mono " + cls);
    input.type = "text";
    input.value = value;
    input.spellcheck = false;
    input.autocomplete = "off";
    input.placeholder = t(placeholderKey);
    input.title = value;
    input.setAttribute("aria-label", t(labelKey));
    input.setAttribute("data-field", field);
    input.setAttribute("data-idx", String(idx));
    return input;
  }

  function buildRule(rule, idx, total) {
    var warnKey = ruleWarning(rule);
    var row = mk("div", "row rule" + (rule.enabled ? "" : " off") + (warnKey ? " invalid" : ""));
    row.setAttribute("role", "listitem");
    row.setAttribute("data-idx", String(idx));

    var sw = buildSegs(true);
    sw.setAttribute("aria-label", t("rule.enable"));
    sw.title = t("rule.enable");
    var swOpts = sw.querySelectorAll(".opt");
    for (var q = 0; q < swOpts.length; q++) {
      swOpts[q].setAttribute("data-action", "toggle");
      swOpts[q].setAttribute("data-idx", String(idx));
    }
    setSwitch(sw, rule.enabled);
    row.appendChild(sw);

    row.appendChild(mk("span", "idx", String(idx + 1)));

    var pickWrap = mk("label", "pick");
    pickWrap.title = t("hint." + rule.scope);
    var sel = mk("select", "");
    sel.setAttribute("aria-label", t("rule.scope"));
    sel.setAttribute("data-field", "scope");
    sel.setAttribute("data-idx", String(idx));
    for (var i = 0; i < SCOPES.length; i++) {
      var opt = mk("option", "", t("scope." + SCOPES[i]));
      opt.value = SCOPES[i];
      if (SCOPES[i] === rule.scope) opt.selected = true;
      sel.appendChild(opt);
    }
    pickWrap.appendChild(sel);
    pickWrap.appendChild(svgIcon("chev", 11, "M4 6l4 4 4-4", "1.8"));
    row.appendChild(pickWrap);

    var pat = buildInput("pat", "pattern", rule.pattern, "rule.pattern", "rule.patternPh", idx);
    row.appendChild(pat);
    row.appendChild(svgIcon("arrow", 12, "M3 8h10M9 4l4 4-4 4", "1.5"));
    row.appendChild(buildInput("rep", "replacement", rule.replacement, "rule.replacement", "rule.replacementPh", idx));

    var acts = mk("span", "acts");
    acts.appendChild(iconBtn("up", "M8 13V3M4 7l4-4 4 4", "rule.up", idx === 0, "up", idx));
    acts.appendChild(iconBtn("down", "M8 3v10M4 9l4 4 4-4", "rule.down", idx === total - 1, "down", idx));
    acts.appendChild(iconBtn("del", "\u00d7", "rule.delete", false, "delete", idx));
    row.appendChild(acts);

    var warn = mk("div", "sub warn", warnKey ? t(warnKey) : "");
    warn.hidden = !warnKey;
    row.appendChild(warn);
    return row;
  }

  function renderRules() {
    var rules = draft.promptRewrite.rules;
    var list = els.list;
    while (list.firstChild) list.removeChild(list.firstChild);
    if (!rules.length) {
      list.appendChild(mk("div", "empty-state", t("rules.empty")));
    } else {
      var frag = document.createDocumentFragment();
      for (var i = 0; i < rules.length; i++) frag.appendChild(buildRule(rules[i], i, rules.length));
      list.appendChild(frag);
    }
    syncAllSegs();
  }

  /** Update only validation visuals of one row (keeps input focus while typing). */
  function refreshRowValidity(idx) {
    var row = els.list.children[idx];
    if (!row || !row.classList.contains("rule")) return;
    var rule = draft.promptRewrite.rules[idx];
    var warnKey = ruleWarning(rule);
    row.classList.toggle("invalid", !!warnKey);
    var pat = row.querySelector('[data-field="pattern"]');
    if (pat) pat.title = rule.pattern;
    var rep = row.querySelector('[data-field="replacement"]');
    if (rep) rep.title = rule.replacement;
    var pick = row.querySelector(".pick");
    if (pick) pick.title = t("hint." + rule.scope);
    var warn = row.querySelector(".sub.warn");
    if (warn) {
      warn.textContent = warnKey ? t(warnKey) : "";
      warn.hidden = !warnKey;
    }
  }

  function renderAll() {
    renderStatic();
    renderToggles();
    renderSummary();
    renderAux();
    renderRules();
    renderFooter();
    syncAllSegs();
  }

  /* ------------------------------------------------------------------ *
   * Auxiliary request routing
   * ------------------------------------------------------------------ */
  function clearNode(n) { while (n.firstChild) n.removeChild(n.firstChild); }

  function effortLabel(e) {
    var k = "effort." + e;
    var v = t(k);
    return v === k ? e : v;
  }

  function auxOption(value, text, selected) {
    var o = document.createElement("option");
    o.value = value;
    o.textContent = text;
    if (selected) o.selected = true;
    return o;
  }

  function auxModelById(id) {
    if (!id) return null;
    for (var i = 0; i < auxState.models.length; i++) if (auxState.models[i].id === id) return auxState.models[i];
    return null;
  }

  function auxDefaultEffort(m) {
    return m.defaultEffort && m.effectiveEfforts.indexOf(m.defaultEffort) >= 0 ? m.defaultEffort : m.effectiveEfforts[0];
  }

  /** Master-switch banner lives outside #aux-body so it stays fully opaque. */
  function renderAuxBanner() {
    var off = auxState.preserveCacheEffort === false;
    els.auxOff.hidden = !off;
    if (off) {
      var src = auxState.preserveSource;
      els.auxOffSrc.textContent = t(src === "provider_ui" ? "aux.off.provider" : (src === "plugins_json" ? "aux.off.plugin" : "aux.off.static"));
    }
    els.auxBody.classList.toggle("inactive", off);
    els.auxAdv.classList.toggle("inactive", off);
  }

  function renderAuxModel() {
    var a = draft.aux;
    var show = a.policy === "fallback_model";
    els.rowAuxModel.hidden = !show;
    els.rowAuxEffort.hidden = !show;

    var cur = a.fallbackModel;
    var m = auxModelById(cur);
    var sel = els.selAuxModel;
    clearNode(sel);
    sel.appendChild(auxOption("", t("aux.model.choose"), !cur));
    if (cur && !m) sel.appendChild(auxOption(cur, auxState.loaded ? t("aux.model.notFound", { id: cur }) : cur, true));
    for (var i = 0; i < auxState.models.length; i++) {
      var mm = auxState.models[i];
      sel.appendChild(auxOption(mm.id, mm.name === mm.id ? mm.id : mm.name + " \u00b7 " + mm.id, mm.id === cur));
    }
    sel.value = cur;
    var shown = cur ? (m ? (m.name === m.id ? m.id : m.name + " \u00b7 " + m.id) : (auxState.loaded ? t("aux.model.notFound", { id: cur }) : cur)) : t("aux.model.choose");
    sel.title = shown;

    var status = auxState.catalogStatus;
    var warn = "";
    if (show && auxState.loaded && !m) {
      if (status === "auth_scope_ambiguous") warn = t("aux.model.ambiguous");
      else if (status === "error") warn = t("aux.model.loadFailed", { err: auxState.catalogError || t("sync.unknownErr") });
      else if (status === "empty") warn = t("aux.model.empty");
      else warn = cur ? t("aux.model.missing") : t("aux.model.unset");
    } else if (show && !cur) {
      warn = t("aux.model.unset");
    }
    els.auxModelWarn.textContent = warn;
    els.auxModelWarn.hidden = !warn;

    var hosted = window.__magpieServiceHosted === true;
    els.auxRefresh.disabled = !hosted || auxRefreshing;
    els.auxRefresh.title = hosted ? t("aux.model.refresh") : t("rules.syncUnavailable");
    els.auxRefresh.setAttribute("aria-label", t("aux.model.refresh"));
    els.auxRefresh.setAttribute("aria-busy", auxRefreshing ? "true" : "false");
  }

  function renderAuxEffort() {
    var a = draft.aux;
    var sel = els.selAuxEffort;
    clearNode(sel);
    var cur = a.fallbackEffort;
    var m = auxModelById(a.fallbackModel);
    var note = "";
    var disabled = false;
    if (m && m.isAliasFixed) {
      var fx = m.fixedEffort || "default";
      sel.appendChild(auxOption(fx, fx, true));
      disabled = true;
      note = t("aux.effort.fixed", { effort: fx });
    } else if (m && m.effectiveEfforts.length === 0) {
      sel.appendChild(auxOption("", t("aux.effort.none"), true));
      disabled = true;
    } else {
      var list = m ? m.effectiveEfforts : AUX_EFFORTS;
      if (list.indexOf(cur) < 0) {
        sel.appendChild(auxOption(cur, effortLabel(cur), true));
        note = t("aux.effort.adapt", { from: effortLabel(cur), to: effortLabel(auxDefaultEffort(m)) });
      }
      for (var i = 0; i < list.length; i++) sel.appendChild(auxOption(list[i], effortLabel(list[i]), list[i] === cur));
      if (!m) note = t("aux.effort.auto");
    }
    if (auxEffortNote) note = t("aux.effort.switched", { from: effortLabel(auxEffortNote.from), to: effortLabel(auxEffortNote.to) });
    sel.disabled = disabled;
    if (!disabled) sel.value = cur;
    var chosen = null;
    var kids = sel.children || [];
    for (var j = 0; j < kids.length; j++) if (kids[j].selected) chosen = kids[j];
    sel.title = chosen ? chosen.textContent : "";
    els.auxEffortNote.textContent = note;
    els.auxEffortNote.hidden = !note;
  }

  function renderAuxNum() {
    var invalid = 0;
    for (var i = 0; i < els.auxNum.length; i++) {
      var n = els.auxNum[i];
      var v = draft.aux[n.def.key];
      var ok = auxNumValid(n.def, v);
      if (n.input.value !== v) n.input.value = v;
      n.input.placeholder = t("aux.num.placeholder", { def: n.def.def });
      n.input.setAttribute("aria-invalid", ok ? "false" : "true");
      n.row.classList.toggle("invalid", !ok);
      n.warn.textContent = ok ? "" : t("aux.num.invalid", { max: n.def.max });
      n.warn.hidden = ok;
      if (!ok) invalid++;
    }
    var changed = auxChangedCount();
    els.auxAdvCount.textContent = changed ? t("aux.adv.changed", { n: changed }) : t("aux.adv.default");
    els.auxAdvCount.classList.toggle("warn", invalid > 0);
    if (invalid > 0) auxAdvOpen = true;   // never leave an invalid value hidden behind a collapsed fold
    renderAuxAdv();
  }

  function renderAuxAdv() {
    els.auxAdvToggle.setAttribute("aria-expanded", auxAdvOpen ? "true" : "false");
    els.auxAdv.hidden = !auxAdvOpen;
  }

  function renderAuxDefaults() {
    els.auxDefaults.textContent = auxArmed ? t("aux.defaultsConfirm") : t("aux.defaults");
    els.auxDefaults.title = t("aux.defaultsTip");
    els.auxDefaults.classList.toggle("armed", auxArmed);
  }

  function renderAux() {
    if (!draft) return;
    setSegValue(els.swAuxPolicy, draft.aux.policy);
    renderAuxBanner();
    renderAuxModel();
    renderAuxEffort();
    renderAuxNum();
    renderAuxDefaults();
    syncAllSegs();
  }

  function disarmAux() {
    if (auxTimer) { clearTimeout(auxTimer); auxTimer = 0; }
    if (auxArmed) {
      auxArmed = false;
      renderAuxDefaults();
    }
  }

  function auxEdited() {
    afterEdit();
    renderAux();
  }

  function onAuxPolicy(val) {
    var v = coercePolicy(val);
    if (!v) return;
    disarmReset();
    draft.aux.policy = v;
    auxEffortNote = null;
    auxEdited();
  }

  function onAuxModelChange() {
    disarmReset();
    var a = draft.aux;
    var prev = a.fallbackEffort;
    a.fallbackModel = els.selAuxModel.value;
    auxEffortNote = null;
    var m = auxModelById(a.fallbackModel);
    // only a user-driven model switch may move the saved effort
    if (m && !m.isAliasFixed && m.effectiveEfforts.length > 0 && m.effectiveEfforts.indexOf(prev) < 0) {
      var to = auxDefaultEffort(m);
      a.fallbackEffort = to;
      auxEffortNote = { from: prev, to: to };
    }
    auxEdited();
  }

  function onAuxEffortChange() {
    if (els.selAuxEffort.disabled) return;
    var v = coerceEffort(els.selAuxEffort.value);
    if (!v) return;
    disarmReset();
    draft.aux.fallbackEffort = v;
    auxEffortNote = null;
    auxEdited();
  }

  function onAuxNumInput(d, input) {
    disarmReset();
    draft.aux[d.key] = input.value;
    afterEdit();
    renderAuxNum();
  }

  /** Blur / change: empty becomes the default, digits drop leading zeros; invalid text stays visible. */
  function onAuxNumCommit(d, input) {
    var v = String(draft.aux[d.key]).trim();
    if (v === "") v = d.def;
    else if (/^\d+$/.test(v)) v = stripZeros(v);
    else v = draft.aux[d.key];
    if (v !== draft.aux[d.key]) {
      draft.aux[d.key] = v;
      afterEdit();
    }
    renderAuxNum();
  }

  function onAuxDefaults() {
    var was = auxArmed;
    disarmReset();
    if (!was) {
      auxArmed = true;
      renderAuxDefaults();
      auxTimer = setTimeout(function () {
        auxTimer = 0;
        auxArmed = false;
        renderAuxDefaults();
      }, 4000);
      return;
    }
    draft.aux = defaultAux();
    auxEffortNote = null;
    auxEdited();
  }

  function onAuxAdvToggle() {
    disarmReset();
    if (auxAdvOpen && auxInvalidCount() > 0) return;
    auxAdvOpen = !auxAdvOpen;
    renderAuxAdv();
  }

  function parseAuxState(r) {
    var data = r && r.data;
    if (!r || !r.res || !r.res.ok || !isObj(data) || data.ok !== true) {
      throw new Error(isObj(data) && typeof data.error === "string" && data.error ? data.error : "HTTP " + (r && r.res ? r.res.status : 0));
    }
    var models = [];
    var raw = Array.isArray(data.models) ? data.models : [];
    for (var i = 0; i < raw.length; i++) {
      var m = raw[i];
      if (!isObj(m) || typeof m.id !== "string" || !m.id) continue;
      var fixed = m.isAliasFixed === true;
      var efforts = [];
      var src = Array.isArray(m.effectiveEfforts) ? m.effectiveEfforts : [];
      for (var j = 0; j < src.length; j++) {
        var e = fixed ? (typeof src[j] === "string" ? src[j] : "") : coerceEffort(src[j]);
        if (e && efforts.indexOf(e) < 0) efforts.push(e);
      }
      models.push({
        id: m.id,
        name: typeof m.name === "string" && m.name ? m.name : m.id,
        effectiveEfforts: efforts,
        defaultEffort: typeof m.defaultEffort === "string" ? m.defaultEffort : "",
        isAliasFixed: fixed,
        fixedEffort: typeof m.fixedEffort === "string" ? m.fixedEffort : ""
      });
    }
    var status = data.catalogStatus;
    if (status !== "ok" && status !== "empty" && status !== "auth_scope_ambiguous" && status !== "error") status = "error";
    var src2 = data.preserveSource;
    if (src2 !== "provider_ui" && src2 !== "plugins_json") src2 = "default";
    return {
      loaded: true,
      preserveCacheEffort: data.preserveCacheEffort !== false,
      preserveSource: src2,
      catalogStatus: status,
      catalogError: typeof data.catalogError === "string" ? data.catalogError : "",
      models: models
    };
  }

  /**
   * Fetch api/aux-routing/state. Never touches draft/saved, so it can never make the page dirty.
   * mode: "init" | "refresh" (?refresh=1, user initiated) | "silent" (visibility).
   */
  function loadAuxState(mode) {
    if (window.__magpieServiceHosted !== true) return Promise.resolve();
    var seq = ++auxSeq;
    var force = mode === "refresh";
    if (force) {
      auxRefreshing = true;
      if (draft) renderAuxModel();
    }
    function request() { return fetchAuxOnce(force); }
    return request().then(function (r) {
      if (isWakeEligibleFailure(r, null)) return wakeServiceAndRetry(new Error("HTTP " + r.res.status), request);
      return r;
    }, function (err) {
      return wakeServiceAndRetry(err, request);
    }).then(function (r) {
      var next = parseAuxState(r);
      if (seq !== auxSeq) return;
      auxState = next;
      if (draft) { renderAuxBanner(); renderAuxModel(); renderAuxEffort(); }
    }).catch(function (err) {
      if (seq !== auxSeq) return;
      if (mode === "init") {
        auxState = { loaded: true, preserveCacheEffort: true, preserveSource: "default", catalogStatus: "error", catalogError: syncErrText(err), models: [] };
        if (draft) { renderAuxBanner(); renderAuxModel(); renderAuxEffort(); }
      } else if (mode === "refresh") {
        setStatus("aux.refreshFailed", "err", true, { err: syncErrText(err) });
      }
    }).then(function () {
      if (force) {
        auxRefreshing = false;
        if (draft) renderAuxModel();
      }
    });
  }

  /** Reveal the app, then measure thumbs once layout exists. */
  function showApp() {
    els.app.hidden = false;
    syncAllSegs();
    if (typeof window.requestAnimationFrame === "function") {
      window.requestAnimationFrame(function () {
        syncAllSegs();
        window.requestAnimationFrame(syncAllSegs);
      });
    }
    if (document.fonts && document.fonts.ready && typeof document.fonts.ready.then === "function") {
      document.fonts.ready.then(syncAllSegs, function () { /* ignore */ });
    }
    if (typeof window.ResizeObserver === "function" && !showApp.ro) {
      try {
        showApp.ro = new window.ResizeObserver(function () { syncAllSegs(); });
        showApp.ro.observe(els.app);
      } catch (e) { /* ignore */ }
    }
  }

  /* ------------------------------------------------------------------ *
   * Actions
   * ------------------------------------------------------------------ */
  function disarmSync() {
    if (syncTimer) { clearTimeout(syncTimer); syncTimer = 0; }
    if (syncArmed) {
      syncArmed = false;
      renderSummary();
    }
  }

  function disarmReset() {
    disarmSync();
    disarmAux();
    if (resetTimer) { clearTimeout(resetTimer); resetTimer = 0; }
    if (resetArmed) {
      resetArmed = false;
      renderSummary();
    }
  }

  function afterEdit(opts) {
    if (statusKind === "ok" || statusKind === "err") {
      if (statusTimer) { clearTimeout(statusTimer); statusTimer = 0; }
      statusKey = ""; statusKind = ""; statusVars = null;
    }
    renderToggles();
    renderSummary();
    if (opts && opts.rules) renderRules();
    renderFooter();
  }

  function onToggle(which, on) {
    disarmReset();
    var s = draft;
    if (which === "master") s.promptSanitizer = on;
    else if (which === "identity") s.promptRewrite.normalize_identity = on;
    else if (which === "tools") s.promptRewrite.sanitize_tools_description = on;
    else if (which === "rewrite") s.promptRewrite.enabled = on;
    afterEdit();
  }

  function onSideload(mode) {
    disarmReset();
    draft.promptRewrite.sideload_mode = normSideload(mode);
    afterEdit();
  }

  function bindSegs(seg, which) {
    seg.addEventListener("click", function (ev) {
      var opt = ev.target && ev.target.closest ? ev.target.closest(".opt") : null;
      if (!opt || !seg.contains(opt)) return;
      if (which === "sideload") { onSideload(opt.getAttribute("data-val")); return; }
      onToggle(which, opt.getAttribute("data-val") === "on");
    });
    seg.addEventListener("keydown", segKey);
  }

  function moveRule(idx, delta) {
    var rules = draft.promptRewrite.rules;
    var to = idx + delta;
    if (idx < 0 || idx >= rules.length || to < 0 || to >= rules.length) return;
    var tmp = rules[idx];
    rules[idx] = rules[to];
    rules[to] = tmp;
    afterEdit({ rules: true });
  }

  function onListClick(ev) {
    var el = ev.target && ev.target.closest ? ev.target.closest("[data-action]") : null;
    if (!el || !els.list.contains(el)) return;
    var idx = parseInt(el.getAttribute("data-idx"), 10);
    var rules = draft.promptRewrite.rules;
    if (isNaN(idx) || idx < 0 || idx >= rules.length) return;
    disarmReset();
    var action = el.getAttribute("data-action");
    if (action === "toggle") {
      rules[idx].enabled = el.getAttribute("data-val") === "on";
      var row = els.list.children[idx];
      if (row) {
        row.classList.toggle("off", !rules[idx].enabled);
        var sw = row.querySelector(".segs");
        if (sw) setSwitch(sw, rules[idx].enabled);
      }
      afterEdit();
    } else if (action === "up") {
      moveRule(idx, -1);
    } else if (action === "down") {
      moveRule(idx, 1);
    } else if (action === "delete") {
      rules.splice(idx, 1);
      afterEdit({ rules: true });
    }
  }

  function onListInput(ev) {
    var el = ev.target;
    if (!el || !el.getAttribute) return;
    var field = el.getAttribute("data-field");
    if (!field) return;
    var idx = parseInt(el.getAttribute("data-idx"), 10);
    var rules = draft.promptRewrite.rules;
    if (isNaN(idx) || idx < 0 || idx >= rules.length) return;
    if (field === "scope") rules[idx].scope = normScope(el.value);
    else if (field === "pattern") rules[idx].pattern = el.value;
    else if (field === "replacement") rules[idx].replacement = el.value;
    else return;
    disarmReset();
    refreshRowValidity(idx);
    afterEdit();
  }

  function onAdd() {
    disarmReset();
    var rules = draft.promptRewrite.rules;
    if (rules.length >= MAX_RULES) return;
    rules.push({ id: newId(), pattern: "", replacement: "", scope: "all", enabled: true });
    afterEdit({ rules: true });
    var inputs = els.list.querySelectorAll('[data-field="pattern"]');
    if (inputs.length) {
      var last = inputs[inputs.length - 1];
      try { last.focus({ preventScroll: true }); } catch (e) { /* ignore */ }
      try { last.scrollIntoView({ block: "center", behavior: "auto" }); } catch (e) { /* ignore */ }
    }
  }

  function onReset() {
    if (!resetArmed) {
      disarmSync();
      disarmAux();
      resetArmed = true;
      renderSummary();
      resetTimer = setTimeout(function () {
        resetTimer = 0;
        resetArmed = false;
        renderSummary();
      }, 4000);
      return;
    }
    if (resetTimer) { clearTimeout(resetTimer); resetTimer = 0; }
    resetArmed = false;
    draft.promptSanitizer = true;
    draft.promptRewrite.enabled = true;
    draft.promptRewrite.normalize_identity = true;
    draft.promptRewrite.sideload_mode = "off";
    draft.promptRewrite.sanitize_tools_description = true;
    draft.promptRewrite.rules = presetRules();
    afterEdit({ rules: true });
  }

  function syncErrText(err) {
    var msg = "";
    try { msg = String((err && err.message) || err || ""); } catch (e) { /* ignore */ }
    msg = msg.replace(/\s+/g, " ").trim();
    if (msg.length > 160) msg = msg.slice(0, 157) + "...";
    return msg || t("sync.unknownErr");
  }

  function syncFail(err) {
    syncing = false;
    renderSync();
    renderFooter();
    setStatus("sync.fail", "err", true, { err: syncErrText(err) });
  }

  function fetchPresetsOnce() {
    try {
      return Promise.resolve(fetch("api/upstream-presets", {
        method: "GET",
        credentials: "omit",
        headers: { accept: "application/json" },
      })).then(function (res) {
        return res.json().then(function (data) {
          return { res: res, data: data, jsonOk: true };
        }, function () {
          return { res: res, data: null, jsonOk: false };
        });
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }

  function sleepMs(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  function isWakeEligibleFailure(r, err) {
    if (err) return true;
    if (!r || !r.res) return true;
    if (r.res.status === 0) return true;
    return r.res.status === 502 && (!r.jsonOk || !isObj(r.data));
  }

  function waitForServiceHealthy(deadlineMs, delayMs) {
    var now = Date.now();
    if (now >= deadlineMs) return Promise.resolve(false);
    return Promise.resolve().then(function () {
      return fetch("health", {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        headers: { accept: "application/json" },
      });
    }).then(function (res) {
      if (!res || res.status !== 200) return false;
      return res.json().then(function (d) {
        return isObj(d) && d.ok === true;
      }, function () {
        return false;
      });
    }, function () {
      return false;
    }).then(function (healthy) {
      if (healthy) return true;
      var rem = deadlineMs - Date.now();
      if (rem <= 0) return false;
      var wait = Math.min(delayMs, rem);
      var nextDelay = Math.min(delayMs * 2, 1000);
      return sleepMs(wait).then(function () {
        return waitForServiceHealthy(deadlineMs, nextDelay);
      });
    });
  }

  function wakeServiceAndRetry(originalErr, retryFn) {
    var deadlineMs = Date.now() + 8000;
    return Promise.resolve().then(function () {
      return fetch("./", { method: "GET", credentials: "omit", cache: "no-store" });
    }).then(function () {
      return null;
    }, function () {
      return null;
    }).then(function () {
      return waitForServiceHealthy(deadlineMs, 250);
    }).then(function (healthy) {
      if (!healthy) throw (originalErr || new Error("HTTP 502"));
      return retryFn();
    });
  }

  function wakeServiceAndRetryPresets(originalErr) {
    return wakeServiceAndRetry(originalErr, fetchPresetsOnce);
  }

  function fetchAuxOnce(forceRefresh) {
    try {
      return Promise.resolve(fetch("api/aux-routing/state" + (forceRefresh ? "?refresh=1" : ""), {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        headers: { accept: "application/json" },
      })).then(function (res) {
        return res.json().then(function (data) {
          return { res: res, data: data, jsonOk: true };
        }, function () {
          return { res: res, data: null, jsonOk: false };
        });
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }

  function onSync() {
    if (syncing || saving || loadError || window.__magpieServiceHosted !== true) return;
    if (!syncArmed) {
      disarmReset();
      syncArmed = true;
      renderSummary();
      syncTimer = setTimeout(function () {
        syncTimer = 0;
        syncArmed = false;
        renderSummary();
      }, 4000);
      return;
    }
    disarmReset();   // also clears the sync confirmation
    syncing = true;
    var before = stateKey(draft);   // edits made while fetching must not be overwritten
    setStatus("", "");
    renderSync();
    renderFooter();
    fetchPresetsOnce().then(function (r) {
      if (isWakeEligibleFailure(r, null)) {
        return wakeServiceAndRetryPresets(new Error("HTTP " + r.res.status));
      }
      return r;
    }, function (err) {
      return wakeServiceAndRetryPresets(err);
    }).then(function (r) {
      var data = r.data;
      if (!r.res.ok || !isObj(data) || data.ok !== true || !Array.isArray(data.rules) || data.rules.length === 0) {
        var why = isObj(data) && data.error ? data.error : "HTTP " + r.res.status;
        throw new Error(why);
      }
      var rules = [];
      for (var i = 0; i < data.rules.length && rules.length < MAX_RULES; i++) {
        if (isObj(data.rules[i])) rules.push(normRule(data.rules[i]));
      }
      if (!rules.length) throw new Error("empty rule list");
      if (stateKey(draft) !== before) {
        syncing = false;
        renderSync();
        setStatus("sync.stale", "err", true);
        return;
      }
      draft.promptSanitizer = true;
      draft.promptRewrite.enabled = true;
      draft.promptRewrite.normalize_identity = true;
      draft.promptRewrite.sideload_mode = "off";
      draft.promptRewrite.sanitize_tools_description = true;
      draft.promptRewrite.rules = rules;
      expanded = true;
      syncing = false;
      renderToggles();
      renderSummary();
      renderRules();
      setStatus(isDirty() ? "sync.ok" : "sync.same", "ok", true, { n: rules.length });
    }).catch(syncFail);
  }

  function onRevert() {
    if (saving || !isDirty()) return;
    disarmReset();
    draft = cloneState(saved);
    auxEffortNote = null;
    renderToggles();
    renderSummary();
    renderAux();
    renderRules();
    setStatus("foot.reverted", "", true);
  }

  function errorKey(err) {
    var msg = "";
    var code = "";
    try {
      msg = String((err && (err.message || err)) || "");
      code = String((err && (err.status || err.code)) || "");
    } catch (e) { /* ignore */ }
    if (/429|rate|too many|limit/i.test(code + " " + msg)) return "foot.rateLimited";
    return "foot.failed";
  }

  function onSave() {
    if (saving || loadError || !isDirty() || auxInvalidCount() > 0) return;
    disarmReset();
    saving = true;
    setStatus("", "");
    renderFooter();
    var payload;
    var snapshot = cloneState(draft);
    var p;
    try {
      payload = buildSaveObject();
      p = Promise.resolve(window.magpie.options.set(payload));
    } catch (e) {
      p = Promise.reject(e);
    }
    p.then(function (result) {
      var next = isObj(result) ? result : payload;
      baseOptions = next;
      saved = normalize(next);
      // keep any edits made while the request was in flight
      var current = stateKey(draft);
      if (current === stateKey(snapshot)) draft = cloneState(saved);
      saving = false;
      renderAux();
      setStatus("foot.saved", "ok", true);
    }).catch(function (err) {
      saving = false;
      setStatus(errorKey(err), "err", true);
    });
  }

  function applyTheme(info) {
    var next = langFrom(info && info.lang);
    if (next === lang && els.app && !els.app.hidden) return;
    lang = next;
    if (draft) { renderAll(); syncAllSegs(); }
  }

  /* ------------------------------------------------------------------ *
   * Init
   * ------------------------------------------------------------------ */
  function bind() {
    els.app = $("app");
    els.swMaster = $("sw-master");
    els.swIdentity = $("sw-identity");
    els.swSideload = $("sw-sideload");
    els.swTools = $("sw-tools");
    els.swRewrite = $("sw-rewrite");
    els.subs = $("subs");
    els.inactiveNote = $("inactive-note");
    els.toggle = $("rules-toggle");
    els.summary = $("rules-summary");
    els.rulesBody = $("rules-body");
    els.add = $("btn-add");
    els.reset = $("btn-reset");
    els.sync = $("btn-sync-upstream");
    els.limit = $("rules-limit");
    els.list = $("rules-list");
    els.note = $("rules-note");
    els.dirty = $("dirty");
    els.status = $("status");
    els.revert = $("btn-revert");
    els.retry = $("btn-retry");
    els.save = $("btn-save");
    els.swAuxPolicy = $("sw-aux-policy");
    els.auxOff = $("aux-off");
    els.auxOffSrc = $("aux-off-src");
    els.auxBody = $("aux-body");
    els.auxAdv = $("aux-adv");
    els.auxAdvToggle = $("aux-adv-toggle");
    els.auxAdvCount = $("aux-adv-count");
    els.auxDefaults = $("btn-aux-defaults");
    els.rowAuxModel = $("row-aux-model");
    els.rowAuxEffort = $("row-aux-effort");
    els.selAuxModel = $("sel-aux-model");
    els.selAuxEffort = $("sel-aux-effort");
    els.auxModelWarn = $("aux-model-warn");
    els.auxEffortNote = $("aux-effort-note");
    els.auxRefresh = $("btn-aux-refresh");
    els.auxNum = [];
    AUX_NUM.forEach(function (d) {
      var sfx = d.input.slice(2);   // "in-aux-min" -> "-aux-min"
      var input = $(d.input);
      var node = { def: d, input: input, row: $("row" + sfx), warn: $("warn" + sfx) };
      els.auxNum.push(node);
      input.addEventListener("input", function () { onAuxNumInput(d, input); });
      input.addEventListener("change", function () { onAuxNumCommit(d, input); });
      input.addEventListener("blur", function () { onAuxNumCommit(d, input); });
    });

    els.swAuxPolicy.addEventListener("click", function (ev) {
      var opt = ev.target && ev.target.closest ? ev.target.closest(".opt") : null;
      if (!opt || !els.swAuxPolicy.contains(opt)) return;
      onAuxPolicy(opt.getAttribute("data-val"));
    });
    els.swAuxPolicy.addEventListener("keydown", segKey);
    els.selAuxModel.addEventListener("change", onAuxModelChange);
    els.selAuxEffort.addEventListener("change", onAuxEffortChange);
    els.auxRefresh.addEventListener("click", function () { disarmReset(); loadAuxState("refresh"); });
    els.auxDefaults.addEventListener("click", onAuxDefaults);
    els.auxAdvToggle.addEventListener("click", onAuxAdvToggle);

    bindSegs(els.swMaster, "master");
    bindSegs(els.swIdentity, "identity");
    bindSegs(els.swSideload, "sideload");
    bindSegs(els.swTools, "tools");
    bindSegs(els.swRewrite, "rewrite");
    els.toggle.addEventListener("click", function () {
      expanded = !expanded;
      disarmReset();
      renderSummary();
    });
    els.add.addEventListener("click", onAdd);
    els.reset.addEventListener("click", onReset);
    els.sync.addEventListener("click", onSync);
    els.list.addEventListener("click", onListClick);
    els.list.addEventListener("keydown", segKey);
    els.list.addEventListener("input", onListInput);
    els.list.addEventListener("change", onListInput);
    els.save.addEventListener("click", onSave);
    els.revert.addEventListener("click", onRevert);
    els.retry.addEventListener("click", onRetry);
  }

  function readOptions() {
    try { return Promise.resolve(window.magpie.options.get()); } catch (e) { return Promise.reject(e); }
  }

  /** Retry a failed settings read. A successful read replaces the draft (edits made on defaults are dropped). */
  function onRetry() {
    if (!loadError || loadingOpts) return;
    loadingOpts = true;
    renderFooter();
    readOptions().then(function (opts) {
      var edited = stateKey(draft) !== stateKey(saved);
      loadingOpts = false;
      loadError = false;
      baseOptions = isObj(opts) ? opts : {};
      saved = normalize(baseOptions);
      draft = cloneState(saved);
      auxEffortNote = null;
      renderAll();
      setStatus(edited ? "foot.reloadedDiscard" : "foot.reloaded", "ok", true);
    }, function () {
      loadingOpts = false;
      renderFooter();
      setStatus("foot.retryFailed", "err", true);
    });
  }

  function init() {
    bind();
    var magpie = window.magpie;
    if (!magpie) {
      // Bridge missing: show defaults, editing stays local and unsaved.
      loadError = true;   // no bridge: nothing can be read or saved
      baseOptions = {};
      saved = normalize({});
      draft = cloneState(saved);
      renderAll();
      showApp();
      return;
    }

    var ready;
    try { ready = Promise.resolve(magpie.ready); } catch (e) { ready = Promise.resolve(null); }
    ready.then(function (info) {
      lang = langFrom(info && info.lang);
      return info;
    }, function () { /* keep default language */ return null; }).then(function (info) {
      // Seamless handoff: static page -> magpie.service (app stays hidden: no flash).
      var svcUrl = typeof magpie.service === "string" && magpie.service ? magpie.service
        : (info && typeof info.service === "string" ? info.service : "");
      if (!window.__magpieServiceHosted && svcUrl) {
        window.location.replace(svcUrl);
        return;
      }
      try {
        if (typeof magpie.onTheme === "function") {
          magpie.onTheme(function (info) {
            try { applyTheme(info); } catch (e) { /* ignore */ }
          });
        }
      } catch (e) { /* ignore */ }
      try {
        // Provider dialog may flip the master switch while this page is hidden: refresh silently on return.
        if (typeof magpie.onVisibility === "function") {
          magpie.onVisibility(function (visible) {
            if (visible === false || !draft || auxRefreshing) return;
            loadAuxState("silent");
          });
        }
      } catch (e) { /* ignore */ }
      return readOptions().catch(function () { loadError = true; return {}; }).then(function (opts) {
        baseOptions = isObj(opts) ? opts : {};
        saved = normalize(baseOptions);
        draft = cloneState(saved);
        renderAll();
        showApp();
        loadAuxState("init");
      });
    }).catch(function () {
      if (!draft) {
        loadError = true;
        baseOptions = {};
        saved = normalize({});
        draft = cloneState(saved);
        renderAll();
        showApp();
      }
    });
  }

  window.addEventListener("error", function (ev) {
    try { ev.preventDefault(); } catch (e) { /* ignore */ }
  });
  window.addEventListener("unhandledrejection", function (ev) {
    try { ev.preventDefault(); } catch (e) { /* ignore */ }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
