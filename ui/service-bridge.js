(function () {
  "use strict";

  /*
   * Magpie page bridge for the service-hosted plugin page.
   *
   * lib/page-service.mjs serves this file instead of `_magpie/bridge.js` once the
   * iframe has navigated to `magpie.service`. It speaks the same postMessage
   * protocol as Magpie's pagebridge.js:
   *   page   -> parent : { magpie: 1, id, method, params }
   *   parent -> page   : { magpie: 1, id, result | error }   (call replies)
   *                      { magpie: 1, event, data }          (theme / visibility)
   * No storage, no eval, no external URLs.
   */

  if (window.__magpieServiceHosted === true && window.magpie) return;
  window.__magpieServiceHosted = true;

  var CALL_TIMEOUT_MS = 30000;
  var root = document.documentElement;
  var parentWin = window.parent;

  var nextId = 1;
  var pending = {};
  var themeCbs = [];
  var visCbs = [];
  var lastTheme = null;
  var lastVisible = true;
  var tokenNames = [];

  /* ---------------- base stylesheet (same defaults as pagebridge.js) ---------------- */
  function injectBase() {
    var css = [
      ":where(html){color-scheme:light dark;background:var(--magpie-bg);color:var(--magpie-fg);}",
      ":where(body){margin:0;background:var(--magpie-bg);color:var(--magpie-fg);font-family:var(--magpie-font,system-ui,-apple-system,\"Segoe UI\",sans-serif);font-size:13px;line-height:1.45;}",
      ":where(code,kbd,samp,pre){font-family:var(--magpie-code,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace);}",
      ":where(button,input,select,textarea){font:inherit;color:inherit;}",
      ":where(input,select,textarea){background:var(--magpie-card);color:var(--magpie-fg);border:1px solid var(--magpie-line);border-radius:6px;}",
      ":where(button){color:var(--magpie-fg);}",
      ":where(a){color:var(--magpie-accent);}",
      ":where(::selection){background:var(--magpie-accent-soft);}"
    ].join("\n");
    var style = document.createElement("style");
    style.setAttribute("data-magpie-base", "");
    style.textContent = css;
    var head = document.head || root;
    head.insertBefore(style, head.firstChild);
  }

  /* ---------------- theme painting ---------------- */
  function paint(info) {
    if (!info || typeof info !== "object") return;
    if (typeof info.dark === "boolean") {
      root.setAttribute("data-theme", info.dark ? "dark" : "light");
      root.style.colorScheme = info.dark ? "dark" : "light only";
    }
    if (typeof info.lang === "string" && info.lang) root.lang = info.lang;
    var tokens = info.tokens;
    if (tokens && typeof tokens === "object") {
      var i;
      for (i = 0; i < tokenNames.length; i++) {
        if (!Object.prototype.hasOwnProperty.call(tokens, tokenNames[i])) {
          root.style.removeProperty("--magpie-" + tokenNames[i]);
        }
      }
      tokenNames = [];
      var keys = Object.keys(tokens);
      for (i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (!/^[A-Za-z0-9_-]+$/.test(k)) continue;
        var v = tokens[k];
        if (typeof v !== "string" && typeof v !== "number") continue;
        root.style.setProperty("--magpie-" + k, String(v));
        tokenNames.push(k);
      }
    }
  }

  function fire(list, arg) {
    var snapshot = list.slice();
    for (var i = 0; i < snapshot.length; i++) {
      try { snapshot[i](arg); } catch (e) { /* listener errors never break the bridge */ }
    }
  }

  function subscribe(list, fn, replay) {
    if (typeof fn !== "function") return function () {};
    list.push(fn);
    if (replay !== undefined && replay !== null) {
      try { fn(replay); } catch (e) { /* ignore */ }
    }
    return function () {
      var idx = list.indexOf(fn);
      if (idx >= 0) list.splice(idx, 1);
    };
  }

  /* ---------------- RPC ---------------- */
  function post(msg) {
    if (!parentWin || parentWin === window) throw new Error("magpie: no parent window");
    parentWin.postMessage(msg, "*");
  }

  function call(method, params) {
    return new Promise(function (resolve, reject) {
      var id = nextId++;
      var timer = setTimeout(function () {
        if (pending[id]) {
          delete pending[id];
          reject(new Error("magpie: " + method + " timed out"));
        }
      }, CALL_TIMEOUT_MS);
      pending[id] = { resolve: resolve, reject: reject, timer: timer };
      try {
        post({ magpie: 1, id: id, method: method, params: params === undefined ? {} : params });
      } catch (e) {
        clearTimeout(timer);
        delete pending[id];
        reject(e);
      }
    });
  }

  function makeError(err) {
    if (err && typeof err === "object") {
      var e = new Error(typeof err.message === "string" ? err.message : "magpie: call failed");
      if (err.code !== undefined) e.code = err.code;
      if (err.status !== undefined) e.status = err.status;
      return e;
    }
    return new Error(typeof err === "string" ? err : "magpie: call failed");
  }

  window.addEventListener("message", function (ev) {
    if (ev.source !== parentWin) return;
    var m = ev.data;
    if (!m || typeof m !== "object" || m.magpie !== 1) return;

    if (typeof m.event === "string") {
      var data = m.data !== undefined ? m.data : m.params;
      if (m.event === "theme") {
        lastTheme = data;
        paint(data);
        fire(themeCbs, data);
      } else if (m.event === "visibility") {
        var visible = data && typeof data === "object" ? data.visible : data;
        lastVisible = visible !== false;
        fire(visCbs, lastVisible);
      }
      return;
    }

    if (typeof m.id === "number" && pending[m.id]) {
      var p = pending[m.id];
      delete pending[m.id];
      clearTimeout(p.timer);
      if (m.error !== undefined && m.error !== null) p.reject(makeError(m.error));
      else p.resolve(m.result);
    }
  });

  /* ---------------- window.magpie ---------------- */
  var magpie = {
    ready: null,
    dark: false,
    lang: "en",
    tokens: {},
    context: null,
    service: null,
    visible: true,
    call: call,
    onTheme: function (fn) { return subscribe(themeCbs, fn); },
    onVisibility: function (fn) { return subscribe(visCbs, fn); },
    options: {
      get: function () { return call("options.get"); },
      set: function (options) { return call("options.set", { options: options }); }
    }
  };
  window.magpie = magpie;

  themeCbs.push(function (info) {
    if (!info || typeof info !== "object") return;
    if (typeof info.dark === "boolean") magpie.dark = info.dark;
    if (typeof info.lang === "string") magpie.lang = info.lang;
    if (info.tokens && typeof info.tokens === "object") magpie.tokens = info.tokens;
  });
  visCbs.push(function (visible) { magpie.visible = visible; });

  injectBase();

  magpie.ready = call("hello").then(function (info) {
    info = info && typeof info === "object" ? info : {};
    paint(info);
    magpie.dark = !!info.dark;
    magpie.lang = typeof info.lang === "string" ? info.lang : "en";
    magpie.tokens = info.tokens && typeof info.tokens === "object" ? info.tokens : {};
    magpie.context = info.context !== undefined ? info.context : null;
    magpie.service = typeof info.service === "string" ? info.service : null;
    magpie.visible = info.visible !== false;
    lastVisible = magpie.visible;
    if (lastTheme === null) lastTheme = info;
    return {
      dark: magpie.dark,
      lang: magpie.lang,
      tokens: magpie.tokens,
      context: magpie.context,
      service: magpie.service,
      visible: magpie.visible
    };
  });
  // Consumers handle rejection themselves; avoid a noisy unhandled rejection otherwise.
  magpie.ready.catch(function () {});
})();
