// dsh-web-pass 网页客户端：「网页密码」设置页
// 会话令牌认证 + 密码强度指示器 + 当前密码验证 + 暗色主题
window.__ModuleLoader__.load({
  id: "dsh-web-pass",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;

    var React = require("react");
    var h = React.createElement;

    var CHANNEL = "/dsh-web-pass";
    var E_STATUS = "webpass.status";
    var E_PW_SET = "webpass.password.set";

    var name = "dsh-web-pass";
    var inject = ["slots", "connection"];

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

    // 密码强度校验（与服务端一致）
    function checkStrength(p) {
      if (!p) return { ok: false, checks: [] };
      var checks = [
        { label: "≥8位", ok: p.length >= 8 },
        { label: "大写", ok: /[A-Z]/.test(p) },
        { label: "小写", ok: /[a-z]/.test(p) },
        { label: "数字", ok: /[0-9]/.test(p) }
      ];
      return { ok: checks.every(function (c) { return c.ok; }), checks: checks };
    }

    function WPSSettingsTab(props) {
      var rpcCall = props.rpcCall;
      var _s = React.useState(null); var status = _s[0]; var setStatus = _s[1];
      var _pw = React.useState(""); var pwInput = _pw[0]; var setPwInput = _pw[1];
      var _cf = React.useState(""); var cfInput = _cf[0]; var setCfInput = _cf[1];
      var _cur = React.useState(""); var curInput = _cur[0]; var setCurInput = _cur[1];
      var _busy = React.useState(false); var busy = _busy[0]; var setBusy = _busy[1];
      var _saved = React.useState(false); var saved = _saved[0]; var setSaved = _saved[1];
      var _err = React.useState(null); var err = _err[0]; var setErr = _err[1];

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

      var save = function (pw, cf, cur) {
        var p = String(pw || "").trim();
        var c = String(cf || "").trim();
        var k = String(cur || "").trim();
        if (!p) { setErr("请输入新密码"); setSaved(false); return; }
        var st = checkStrength(p);
        if (!st.ok) { setErr("密码强度不足：需≥8位，含大写字母、小写字母和数字"); setSaved(false); return; }
        if (!c) { setErr("请再次输入确认密码"); setSaved(false); return; }
        if (p !== c) { setErr("两次输入的密码不一致"); setSaved(false); return; }
        setBusy(true); setSaved(false); setErr(null);
        rpcCall(E_PW_SET, { password: p, confirm: c, current: k }).then(function (r) {
          if (r && r.ok) { setSaved(true); setPwInput(""); setCfInput(""); setCurInput(""); }
          else { setErr((r && r.error && r.error.message) || "保存失败"); }
        }).catch(function (e) { setErr(String((e && e.message) || e)); })
          .finally(function () { setBusy(false); });
      };

      var logout = function () {
        setBusy(true); setErr(null);
        fetch("/gate/logout", { method: "POST" }).then(function () {
          location.reload();
        }).catch(function (e) { setBusy(false); setErr("退出失败：" + e.message); });
      };

      var children = [];
      children.push(h("strong", null, "网页密码 | Web password settings"));
      children.push(h("div", { style: V.muted }, "设置网页访问密码（密码以 scrypt 哈希存储）| configure the web access password"));

      // 网关状态
      var sb = [];
      if (status) {
        sb.push(h("div", { style: V.row }, "代理状态：", status.proxyRunning ? "运行中" : "未运行", "（端口 ", String(status.proxyPort ?? "-"), "）"));
        if (status.lanUrl) sb.push(h("div", { style: V.row }, "局域网地址：", h("span", { style: V.code }, status.lanUrl)));
        sb.push(h("div", { style: V.row }, "dsh web 端口：", String(status.dshPort ?? "-")));
      } else {
        sb.push(h("div", { style: V.muted }, "正在读取状态… | loading…"));
      }
      children.push(h("div", { style: V.block }, h("div", { style: { fontWeight: 600, fontSize: 13 } }, "网关状态 | gateway status"), sb));

      // 密码强度指示器
      var pwSt = checkStrength(pwInput);
      var strengthEl = pwInput ? h("div", { style: { display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 } },
        pwSt.checks.map(function (c, i) {
          return h("span", { key: i, style: { fontSize: 11, padding: "2px 6px", borderRadius: 4, border: "1px solid " + (c.ok ? "var(--dsw-alias-state-success-primary,#16a34a)" : "var(--dsw-alias-border-l2,#d1d5db)"), color: c.ok ? "var(--dsw-alias-state-success-primary,#16a34a)" : "var(--dsw-alias-label-tertiary,#8b93a1)" } }, (c.ok ? "✓ " : "") + c.label);
        })
      ) : null;

      // 密码修改区
      var pc = [];
      pc.push(h("div", { style: V.muted }, "设置访问密码（保存后旧密码立即作废，其他会话全部吊销）"));
      if (status) {
        pc.push(h("div", null,
          h("div", { style: V.row }, "当前密码："),
          h("input", { type: "password", value: curInput, onChange: function (e) { return setCurInput(e.target.value); }, placeholder: "输入当前密码（修改时必须）| Current password", style: V.input, autoComplete: "current-password" })));
      }
      pc.push(h("input", { type: "password", value: pwInput, onChange: function (e) { return setPwInput(e.target.value); }, placeholder: "新密码（≥8位，含大小写字母和数字）", style: V.input, autoComplete: "new-password" }));
      pc.push(strengthEl);
      pc.push(h("input", { type: "password", value: cfInput, onChange: function (e) { return setCfInput(e.target.value); }, placeholder: "再次输入新密码（确认）", style: V.input, autoComplete: "new-password" }));
      pc.push(h("div", { style: { display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" } },
        h("button", { style: V.primary, onClick: function () { return save(pwInput, cfInput, curInput); }, disabled: busy }, busy ? "处理中…" : "保存密码 | Save")));
      if (saved) pc.push(h("div", { style: { color: "var(--dsw-alias-state-success-primary,#16a34a)", fontSize: 12, marginTop: 8 } }, "✅ 密码已保存（其他会话已吊销）| saved, other sessions revoked"));
      if (err) pc.push(h("div", { style: { color: "var(--dsw-alias-state-error-primary,#dc2626)", fontSize: 12, marginTop: 8 } }, "❌ " + err));
      children.push(h("div", { style: V.block }, h("div", { style: { fontWeight: 600, fontSize: 13 } }, "访问密码 | web password"), pc));

      // 登出按钮
      children.push(h("div", { style: V.block },
        h("button", { style: { ...V.ghost, width: "100%", justifyContent: "center" }, onClick: logout, disabled: busy }, "🚪 退出登录 | Logout")));

      children.push(h("div", { style: V.block },
        h("a", { href: "/dsh-logs/", target: "_blank", rel: "noreferrer", style: Object.assign({}, V.ghost, { textDecoration: "none", width: "100%", justifyContent: "center" }) },
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
