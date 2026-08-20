// dsh-web-pass 网页客户端：设置页签「网页密码」。
// 布局与加载格式对齐 dsh-market / dsh-pocket（window.__ModuleLoader__.load 运行时模块加载，
// 由 modules 节点半动态 /plugins/dsh-web-pass/client.js 提供，无需重打 shell dist）。
window.__ModuleLoader__.load({
  id: "dsh-web-pass",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;

    var React = require("react");
    var h = React.createElement;

    // ---- 与 lib/web-rpc.js 对齐的 RPC 契约 ----
    var CHANNEL = "/dsh-web-pass";
    var E_STATUS = "webpass.status";
    var E_PW_SET = "webpass.password.set";
    var E_PW_RANDOM = "webpass.password.random";

    var name = "dsh-web-pass";
    var inject = ["slots", "connection"];

    // DSH 设计系统变量（带兜底值，缺变量也可读）
    var V = {
      card: { background: "var(--dsw-alias-bg-layer-1,#fff)", border: "1px solid var(--dsw-alias-border-l2,#e5e7eb)", borderRadius: 12, padding: "16px 20px", maxWidth: 500 },
      block: { borderTop: "1px solid var(--dsw-alias-border-l2,#e5e7eb)", marginTop: 16, paddingTop: 16 },
      muted: { color: "var(--dsw-alias-label-tertiary,#8b93a1)", fontSize: 12, lineHeight: 1.5 },
      code: { fontFamily: "ui-monospace,Menlo,monospace", fontSize: 13, wordBreak: "break-all", margin: "8px 0 4px", padding: "8px 10px", background: "var(--dsw-alias-bg-layer-2,#f3f4f6)", borderRadius: 6, color: "var(--dsw-alias-label-primary,inherit)" },
      row: { margin: "10px 0", fontSize: 13, lineHeight: 1.6, color: "var(--dsw-alias-label-primary,inherit)" },
      input: { width: "100%", boxSizing: "border-box", padding: "9px 12px", fontSize: 13, border: "1px solid var(--dsw-alias-border-l2,#d1d5db)", borderRadius: 8, outline: "none", marginTop: 8, background: "var(--dsw-alias-bg-layer-1,#fff)", color: "inherit" },
      primary: { font: "inherit", cursor: "pointer", border: "none", background: "var(--dsw-alias-button-primary-fill, var(--dsw-alias-brand-primary,#4f6ef7))", color: "var(--dsw-alias-label-primary-foreground,#fff)", height: 36, padding: "0 16px", borderRadius: 999, fontSize: 13, fontWeight: 500, display: "inline-flex", alignItems: "center", justifyContent: "center" },
      ghost: { font: "inherit", cursor: "pointer", border: "1px solid var(--dsw-alias-button-ghost-active-border, var(--dsw-alias-border-l2,#d1d5db))", background: "var(--dsw-alias-bg-layer-1,#fff)", color: "var(--dsw-alias-label-primary,inherit)", height: 36, padding: "0 16px", borderRadius: 999, fontSize: 13, display: "inline-flex", alignItems: "center", justifyContent: "center" }
    };

    function WPSSettingsTab(props) {
      var rpcCall = props.rpcCall;
      var _s = React.useState(null); var status = _s[0]; var setStatus = _s[1];
      var _pw = React.useState(""); var pwInput = _pw[0]; var setPwInput = _pw[1];
      var _cf = React.useState(""); var cfInput = _cf[0]; var setCfInput = _cf[1];
      var _busy = React.useState(false); var busy = _busy[0]; var setBusy = _busy[1];
      var _saved = React.useState(false); var saved = _saved[0]; var setSaved = _saved[1];
      var _err = React.useState(null); var err = _err[0]; var setErr = _err[1];
      var _newPw = React.useState(null); var newPw = _newPw[0]; var setNewPw = _newPw[1];

      React.useEffect(function () {
        var alive = true;
        var load = function () {
          try {
            rpcCall(E_STATUS, {}).then(function (r) { if (alive && r && r.ok) setStatus(r.value); }).catch(function () {});
          } catch (e) {}
        };
        load();
        var t = setInterval(load, 3000);
        return function () { alive = false; clearInterval(t); };
      }, []);

      var save = function (pw, cf) {
        var p = String(pw || "").trim();
        var c = String(cf || "").trim();
        if (!p) { setErr("请输入新密码"); setSaved(false); return; }
        if (/^\d+$/.test(p)) { setErr("密码不能是纯数字（至少含字母）"); setSaved(false); return; }
        if (!c) { setErr("请再次输入确认密码"); setSaved(false); return; }
        if (p !== c) { setErr("两次输入的密码不一致"); setSaved(false); return; }
        setBusy(true); setSaved(false); setErr(null); setNewPw(null);
        rpcCall(E_PW_SET, { password: p, confirm: c }).then(function (r) {
          if (r && r.ok) { setSaved(true); setPwInput(""); setCfInput(""); }
          else { setErr((r && r.error && r.error.message) || "保存失败"); }
        }).catch(function (e) { setErr(String((e && e.message) || e)); })
          .finally(function () { setBusy(false); });
      };

      var randomize = function () {
        setBusy(true); setErr(null); setSaved(false); setNewPw(null);
        rpcCall(E_PW_RANDOM, {}).then(function (r) {
          if (r && r.ok && typeof r.value.password === "string") { setNewPw(r.value.password); setPwInput(""); }
          else { setErr((r && r.error && r.error.message) || "生成失败"); }
        }).catch(function (e) { setErr(String((e && e.message) || e)); })
          .finally(function () { setBusy(false); });
      };

      var children = [];
      children.push(h("strong", null, "网页密码 | Web password settings"));
      children.push(h("div", { style: V.muted }, "设置网页访问密码 | configure the web access password"));

      var sb = [];
      if (status) {
        sb.push(h("div", { style: V.row }, "代理状态：", status.proxyRunning ? "运行中" : "未运行", "（端口 ", String(status.proxyPort ?? "-"), "）"));
        if (status.lanUrl) sb.push(h("div", { style: V.row }, "局域网地址：", h("span", { style: V.code }, status.lanUrl)));
        sb.push(h("div", { style: V.row }, "dsh web 端口：", String(status.dshPort ?? "-")));
      } else {
        sb.push(h("div", { style: V.muted }, "正在读取状态… | loading…"));
      }
      children.push(h("div", { style: V.block }, h("div", { style: { fontWeight: 600, fontSize: 13 } }, "网关状态 | gateway status"), sb));

      var pc = [];
      pc.push(h("div", { style: V.muted }, "设置访问密码（成功保存后旧密码立即作废，所有已登录设备需重新输入）"));
      pc.push(h("input", { type: "password", value: pwInput, onChange: function (e) { return setPwInput(e.target.value); }, placeholder: "输入新密码（不能纯数字）| New password (letters required)", style: V.input, autoComplete: "one-time-code" }));
      pc.push(h("input", { type: "password", value: cfInput, onChange: function (e) { return setCfInput(e.target.value); }, placeholder: "再次输入新密码（确认）| Re-enter to confirm", style: V.input, autoComplete: "one-time-code" }));
      pc.push(h("div", { style: { display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" } },
        h("button", { style: V.primary, onClick: function () { return save(pwInput, cfInput); }, disabled: busy }, busy ? "处理中…" : "保存密码 | Save"),
        h("button", { style: V.ghost, onClick: randomize, disabled: busy }, busy ? "生成中…" : "🔑 一键随机换密码 | Random")));
      if (saved) pc.push(h("div", { style: { color: "#16a34a", fontSize: 12, marginTop: 8 } }, "✅ 密码已保存 | password saved"));
      if (err) pc.push(h("div", { style: { color: "#dc2626", fontSize: 12, marginTop: 8 } }, "❌ " + err));
      if (newPw) pc.push(
        h("div", { style: { border: "1px solid var(--dsw-alias-state-warn-primary,#b45309)", borderRadius: 8, padding: "10px 12px", marginTop: 10, background: "var(--dsw-alias-bg-layer-2,#f3f4f6)" } },
          h("div", { style: { fontWeight: 600, fontSize: 13 } }, "🔑 新密码已生效（请先记下）| new password — save it"),
          h("div", { style: V.code }, newPw),
          h("div", { style: { fontSize: 12, color: "#b45309", lineHeight: 1.5 } }, "旧密码已作废；刷新/重开页面后需用这个新密码重新登录。| old password is void; re-login needed after reload.")));
      children.push(h("div", { style: V.block }, h("div", { style: { fontWeight: 600, fontSize: 13 } }, "访问密码 | web password"), pc));

      children.push(h("div", { style: V.block },
        h("a", { href: "/dsh-logs/", target: "_blank", rel: "noreferrer", style: Object.assign({}, V.ghost, { textDecoration: "none" }) },
          "📄 访问日志（谁在试密码）| Access log")));

      return h("div", { style: V.card }, children);
    }

    function apply(ctx) {
      var rpcCall = function (endpoint, payload, signal) {
        return ctx.connection.rpc.call(CHANNEL, endpoint, payload, signal);
      };
      ctx.slots.inject("settings.section", function () {
        return ctx.slots.register({
          name: "settings.section",
          id: "dsh-web-pass",
          order: 2,
          label: function () { return "网页密码"; },
          inject: function () { return { rpcCall: rpcCall }; }
        }, WPSSettingsTab);
      });
    }

    exports.apply = apply;
    exports.name = name;
    exports.inject = inject;
    return module.exports;
  }
});
