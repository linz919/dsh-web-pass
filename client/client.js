// dsh-web-pass 网页客户端：「网页密码」设置页
// 上游表（表单新增 + 密码重设 + 开关/删除） + 统一密码重设框 + 暗色主题
window.__ModuleLoader__.load({
  id: "dsh-web-pass",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;

    var React = require("react");
    var h = React.createElement;

    var CHANNEL = "/api";
    var E_STATUS = "webpass.status";
    var E_PW_SET = "webpass.password.set";
    var E_ENTRY_SET = "webpass.entry.set";
    var E_ENTRY_DEL = "webpass.entry.del";
    var E_ENTRY_ADD = "webpass.entry.add";

    var name = "dsh-web-pass";
    var inject = ["slots", "connection"];

    var V = {
      card: { background: "var(--dsw-alias-bg-layer-1,#fff)", border: "1px solid var(--dsw-alias-border-l2,#e5e7eb)", borderRadius: 12, padding: "16px 20px", maxWidth: 640 },
      block: { borderTop: "1px solid var(--dsw-alias-border-l2,#e5e7eb)", marginTop: 16, paddingTop: 16 },
      muted: { color: "var(--dsw-alias-label-tertiary,#8b93a1)", fontSize: 12, lineHeight: 1.5 },
      code: { fontFamily: "ui-monospace,Menlo,monospace", fontSize: 12, wordBreak: "break-all", margin: "8px 0 4px", padding: "8px 10px", background: "var(--dsw-alias-bg-layer-2,#f3f4f6)", borderRadius: 6, color: "var(--dsw-alias-label-primary,inherit)", whiteSpace: "pre-wrap" },
      row: { margin: "10px 0", fontSize: 13, lineHeight: 1.6, color: "var(--dsw-alias-label-primary,inherit)" },
      input: { width: "100%", boxSizing: "border-box", padding: "9px 12px", fontSize: 13, border: "1px solid var(--dsw-alias-border-l2,#d1d5db)", borderRadius: 8, outline: "none", marginTop: 8, background: "var(--dsw-alias-bg-layer-1,#fff)", color: "inherit" },
      inpSm: { width: "100%", boxSizing: "border-box", padding: "6px 10px", fontSize: 12, border: "1px solid var(--dsw-alias-border-l2,#d1d5db)", borderRadius: 8, outline: "none", background: "var(--dsw-alias-bg-layer-1,#fff)", color: "inherit" },
      primary: { font: "inherit", cursor: "pointer", border: "none", background: "var(--dsw-alias-button-primary-fill, var(--dsw-alias-brand-primary,#4f6ef7))", color: "var(--dsw-alias-label-primary-foreground,#fff)", height: 36, padding: "0 16px", borderRadius: 999, fontSize: 13, fontWeight: 500, display: "inline-flex", alignItems: "center", justifyContent: "center" },
      ghost: { font: "inherit", cursor: "pointer", border: "1px solid var(--dsw-alias-button-ghost-active-border, var(--dsw-alias-border-l2,#d1d5db))", background: "var(--dsw-alias-bg-layer-1,#fff)", color: "var(--dsw-alias-label-primary,inherit)", height: 32, padding: "0 12px", borderRadius: 999, fontSize: 12, display: "inline-flex", alignItems: "center", justifyContent: "center", marginRight: 6, marginBottom: 4 },
      table: { width: "100%", borderCollapse: "collapse", fontSize: 13 },
      th: { textAlign: "left", padding: "8px 10px", borderBottom: "1px solid var(--dsw-alias-border-l2,#e5e7eb)", color: "var(--dsw-alias-label-tertiary,#8b93a1)", fontSize: 12, fontWeight: 600 },
      td: { textAlign: "left", padding: "8px 10px", borderBottom: "1px solid var(--dsw-alias-border-l2,#e5e7eb)", verticalAlign: "middle" },
      dotOk: { display: "inline-block", width: 9, height: 9, borderRadius: "50%", background: "var(--dsw-alias-state-success-primary,#16a34a)", marginRight: 6 },
      dotBad: { display: "inline-block", width: 9, height: 9, borderRadius: "50%", background: "var(--dsw-alias-state-error-primary,#dc2626)", marginRight: 6 },
      sw: { position: "relative", display: "inline-block", width: 38, height: 22, verticalAlign: "middle" },
      swIn: { opacity: 0, width: 0, height: 0, margin: 0 }
    };
    function swSl(on) { return { position: "absolute", inset: 0, background: on ? "var(--dsw-alias-state-success-primary,#16a34a)" : "#cbd5e1", borderRadius: 22, transition: ".2s", cursor: "pointer" }; }
    function swKn(on) { return { position: "absolute", width: 16, height: 16, left: 3, top: 3, background: "#fff", borderRadius: "50%", transition: ".2s", transform: on ? "translateX(16px)" : "none" }; }

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

    var HELP_YAML = "# cordis.patch.yml（patch 行与页面新增行共存）\n" +
      "upstreams:\n" +
      "  - label: 访客\n" +
      "    passwordEnv: DSH_GUEST_PASS\n" +
      "    host: 127.0.0.1\n" +
      "    port: 3085\n" +
      "    clientHostTrust: false  # 访客关\n" +
      "    dsh: true  # 非 DSH 后端设 false\n" +
      "# patch 行改后重起 dsh web；本页新增行存数据目录、重启保留";

    function WPSSettingsTab(props) {
      var rpcCall = props.rpcCall;
      var _s = React.useState(null); var status = _s[0]; var setStatus = _s[1];
      var _ei = React.useState(null); var entryIdx = _ei[0]; var setEntryIdx = _ei[1];
      var _pw = React.useState(""); var pwInput = _pw[0]; var setPwInput = _pw[1];
      var _cf = React.useState(""); var cfInput = _cf[0]; var setCfInput = _cf[1];
      var _busy = React.useState(false); var busy = _busy[0]; var setBusy = _busy[1];
      var _saved = React.useState(false); var saved = _saved[0]; var setSaved = _saved[1];
      var _err = React.useState(null); var err = _err[0]; var setErr = _err[1];
      var _help = React.useState(false); var showHelp = _help[0]; var setShowHelp = _help[1];
      var _al = React.useState(""); var addLabel = _al[0]; var setAddLabel = _al[1];
      var _au = React.useState(""); var addUp = _au[0]; var setAddUp = _au[1];
      var _ad = React.useState(false); var addDsh = _ad[0]; var setAddDsh = _ad[1];
      var _ae = React.useState(null); var addErr = _ae[0]; var setAddErr = _ae[1];

      var load = function () {
        try {
          rpcCall(E_STATUS, {}).then(function (r) { if (r && r.ok) setStatus(r.value); }).catch(function () {});
        } catch (e) {}
      };
      React.useEffect(function () {
        load();
        var t = setInterval(load, 3000);
        return function () { clearInterval(t); };
      }, []);

      var entries = (status && status.entries) || [];
      // 只显示可见条目（软删行 visible=false 不渲染）；序号仍用服务端原始下标
      var visRows = [];
      entries.forEach(function (e, i) { if (e.visible !== false) visRows.push({ e: e, i: i }); });
      // 默认选中第一个非管理员可见条目；选中项被删/隐藏时回落
      var effIdx = entryIdx;
      if (effIdx === null || effIdx === undefined || !entries[effIdx] || entries[effIdx].visible === false) {
        effIdx = 0;
        for (var k = 0; k < visRows.length; k++) {
          if (visRows[k].i !== 0) { effIdx = visRows[k].i; break; }
        }
      }

      // 新增上游：{label, host, port, dsh} → 默认停用、无密码
      var addUpstream = function () {
        var lb = String(addLabel || "").trim();
        var up = String(addUp || "").trim();
        if (!lb) { setAddErr("请填写标签"); return; }
        var ci = up.lastIndexOf(":");
        var host, portStr;
        if (ci >= 0) { host = up.slice(0, ci).trim() || "127.0.0.1"; portStr = up.slice(ci + 1).trim(); }
        else { host = "127.0.0.1"; portStr = up; }
        var port = Number(portStr);
        if (!portStr || !Number.isInteger(port) || port <= 0 || port > 65535) { setAddErr("上游格式：host:port，端口 1-65535（如 127.0.0.1:3085）"); return; }
        setBusy(true); setAddErr(null);
        var timer = setTimeout(function () {
          setBusy(false);
          setAddErr("新增请求超过 8 秒仍无响应。请看 dsh 日志中的“新增上游请求/成功/失败”记录。");
        }, 8000);
        rpcCall(E_ENTRY_ADD, { label: lb, host: host, port: port, dsh: addDsh }).then(function (r) {
          clearTimeout(timer);
          if (r && r.ok) {
            var v = r.value || {};
            var ne = v.entry || { label: lb, host: host, port: port, dsh: addDsh, enabled: false, visible: true, reachable: null, holding: false };
            setStatus(function (old) {
              var base = old || { entries: [] };
              var arr = (base.entries || []).slice();
              var idx = Number.isInteger(v.index) ? v.index : arr.length;
              arr[idx] = { ...ne, visible: true, reachable: null };
              return { ...base, entries: arr };
            });
            setAddLabel(""); setAddUp(""); setAddDsh(false); setBusy(false);
            setTimeout(load, 0);
          } else {
            setBusy(false);
            setAddErr((r && r.error && r.error.message) || "新增失败：服务器没有返回成功结果");
          }
        }).catch(function (e) {
          clearTimeout(timer);
          setBusy(false);
          setAddErr("新增请求失败：" + String((e && e.message) || e));
        });
      };

      var save = function () {
        var p = String(pwInput || "").trim();
        var c = String(cfInput || "").trim();
        if (!p) { setErr("请输入新密码"); setSaved(false); return; }
        var st = checkStrength(p);
        if (!st.ok) { setErr("密码强度不足：需≥8位，含大写字母、小写字母和数字"); setSaved(false); return; }
        if (!c) { setErr("请再次输入确认密码"); setSaved(false); return; }
        if (p !== c) { setErr("两次输入的密码不一致"); setSaved(false); return; }
        setBusy(true); setSaved(false); setErr(null);
        rpcCall(E_PW_SET, { entry: effIdx, password: p, confirm: c }).then(function (r) {
          if (r && r.ok) { setSaved(true); setPwInput(""); setCfInput(""); load(); }
          else { setErr((r && r.error && r.error.message) || "保存失败"); }
        }).catch(function (e) { setErr(String((e && e.message) || e)); })
          .finally(function () { setBusy(false); });
      };

      var flip = function (i, on) {
        setBusy(true); setErr(null);
        rpcCall(E_ENTRY_SET, { entry: i, enabled: on }).then(function (r) {
          if (!(r && r.ok)) setErr((r && r.error && r.error.message) || "操作失败");
          load();
        }).catch(function (e) { setErr(String((e && e.message) || e)); })
          .finally(function () { setBusy(false); });
      };

      var del = function (i, label) {
        if (!window.confirm("删除【" + label + "】？该密码立即作废，其会话全部吊销（patch 里删行重起则彻底消失）。")) return;
        setBusy(true); setErr(null);
        rpcCall(E_ENTRY_DEL, { entry: i }).then(function (r) {
          if (!(r && r.ok)) setErr((r && r.error && r.error.message) || "操作失败");
          load();
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
      children.push(h("div", { style: V.muted }, "一个密码进一个后端（主人 / 访客 / 工具间）| one password, one upstream"));

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

      // 上游表（首行 = 新增表单：标签 / 上游 / DSH 开关 + 增加按钮）
      var rows = visRows.map(function (x) {
        var e = x.e; var i = x.i;
        var ops = [h("button", {
          key: "pw", style: V.ghost, disabled: busy,
          onClick: function () { setEntryIdx(i); }
        }, "密码重设")];
        if (i !== 0) {
          ops.push(h("label", { key: "sw", style: V.sw, title: "启用/停用" },
            h("input", { type: "checkbox", checked: !!e.enabled, style: V.swIn, disabled: busy, onChange: function (ev) { flip(i, ev.target.checked); } }),
            h("span", { style: swSl(!!e.enabled) }, h("span", { style: swKn(!!e.enabled) }))));
          ops.push(h("button", { key: "del", style: V.ghost, disabled: busy, onClick: function () { del(i, e.label); } }, "删除"));
        }
        return h("tr", { key: i },
          h("td", { style: V.td }, h("span", { style: e.reachable ? V.dotOk : V.dotBad }), e.reachable ? "通" : "不通"),
          h("td", { style: V.td }, String(e.label ?? "")),
          h("td", { style: V.td }, String(e.host ?? "") + ":" + String(e.port ?? "")),
          h("td", { style: V.td }, ops));
      });
      var addFormRow = h("tr", { key: "add" },
        h("td", { style: V.td }, h("span", { style: { color: "var(--dsw-alias-label-tertiary,#8b93a1)" } }, "＋")),
        h("td", { style: V.td }, h("input", { value: addLabel, onChange: function (ev) { setAddLabel(ev.target.value); }, placeholder: "标签，如 访客", style: V.inpSm, disabled: busy, maxLength: 32 })),
        h("td", { style: V.td }, h("input", { value: addUp, onChange: function (ev) { setAddUp(ev.target.value); }, placeholder: "host:port，如 127.0.0.1:3085", style: V.inpSm, disabled: busy, onKeyDown: function (ev) { if (ev.key === "Enter") addUpstream(); } })),
        h("td", { style: V.td, whiteSpace: "nowrap" },
          h("label", { style: { display: "inline-flex", alignItems: "center", marginRight: 8, cursor: "pointer" }, title: "后端是 DSH（需要代持/改写）时打开；openclaw 等保持关闭" },
            h("label", { style: { ...V.sw, width: 30, height: 18, verticalAlign: "middle" } },
              h("input", { type: "checkbox", checked: addDsh, style: V.swIn, disabled: busy, onChange: function (ev) { setAddDsh(ev.target.checked); } }),
              h("span", { style: { ...swSl(addDsh), borderRadius: 18 } }, h("span", { style: { ...swKn(addDsh), width: 12, height: 12, transform: addDsh ? "translateX(12px)" : "none" } }))),
            h("span", { style: { fontSize: 11, color: "var(--dsw-alias-label-tertiary,#8b93a1)", marginLeft: 4 } }, "DSH")),
          h("button", { style: { ...V.primary, height: 28, padding: "0 12px", fontSize: 12 }, onClick: addUpstream, disabled: busy }, "增加")));
      var tbl = h("div", null,
        h("table", { style: V.table },
          h("thead", null, h("tr", null,
            h("th", { style: V.th }, "状态"), h("th", { style: V.th }, "标签"),
            h("th", { style: V.th }, "上游"), h("th", { style: V.th }, "操作"))),
          h("tbody", null, [addFormRow].concat(rows.length ? rows : [h("tr", { key: "empty" }, h("td", { colSpan: 4, style: V.td }, "暂无条目"))]))),
        h("div", { style: { ...V.muted, marginTop: 8 } }, "新条目默认停用、无密码：在下方「密码重设」选中它设好密码，再打开行内开关。删除为软删（其余条目序号不变）| new rows start disabled without a password"),
        h("div", { style: { ...V.muted, marginTop: 4 } }, "💡 同浏览器一次只保留一个登录身份（cookie 全浏览器共享）：要用多个身份同时在线，请开多个隐身窗口分别登录对应条目，无需退出 DSH | one identity per browser; use separate incognito windows to hold multiple entry logins side by side",
        h("div", { style: { ...V.muted, marginTop: 4 } }, "🛠 0.3.7：新增成功先立即显示，后台再刷新连通状态；若 8 秒无响应，会明确提示并可结合 dsh 日志定位 | immediate add acknowledgement + background probe")),
        addErr ? h("div", { style: { color: "var(--dsw-alias-state-error-primary,#dc2626)", fontSize: 12, marginTop: 6 } }, "❌ " + addErr) : null,
        h("div", { style: { marginTop: 6 } },
          h("a", { href: "#", onClick: function (ev) { ev.preventDefault(); setShowHelp(!showHelp); }, style: { ...V.muted, textDecoration: "underline" } },
            showHelp ? "收起 patch 配置示例" : "patch 配置示例（结构也可用文件配置）")),
        showHelp ? h("div", { style: V.code }, HELP_YAML) : null);
      children.push(h("div", { style: V.block }, h("div", { style: { fontWeight: 600, fontSize: 13 } }, "上游表 | upstreams"), tbl));

      // 统一密码重设框
      var pwSt = checkStrength(pwInput);
      var strengthEl = pwInput ? h("div", { style: { display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 } },
        pwSt.checks.map(function (c, i) {
          return h("span", { key: i, style: { fontSize: 11, padding: "2px 6px", borderRadius: 4, border: "1px solid " + (c.ok ? "var(--dsw-alias-state-success-primary,#16a34a)" : "var(--dsw-alias-border-l2,#d1d5db)"), color: c.ok ? "var(--dsw-alias-state-success-primary,#16a34a)" : "var(--dsw-alias-label-tertiary,#8b93a1)" } }, (c.ok ? "✓ " : "") + c.label);
        })
      ) : null;
      var pc = [];
      pc.push(h("div", { style: V.muted }, "保存后旧密码立即作废，其他会话全部吊销"));
      pc.push(h("select", {
        value: String(effIdx),
        onChange: function (e) { setEntryIdx(Number(e.target.value)); setSaved(false); },
        style: V.input
      }, visRows.map(function (x) { return h("option", { key: x.i, value: String(x.i) }, String(x.e.label ?? "")); })));
      pc.push(h("input", { type: "password", value: pwInput, onChange: function (e) { return setPwInput(e.target.value); }, placeholder: "新密码（≥8位，含大小写字母和数字）", style: V.input, autoComplete: "new-password" }));
      pc.push(strengthEl);
      pc.push(h("input", { type: "password", value: cfInput, onChange: function (e) { return setCfInput(e.target.value); }, placeholder: "再次输入新密码（确认）", style: V.input, autoComplete: "new-password" }));
      pc.push(h("div", { style: { display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" } },
        h("button", { style: V.primary, onClick: save, disabled: busy }, busy ? "处理中…" : "保存 | Save")));
      if (saved) pc.push(h("div", { style: { color: "var(--dsw-alias-state-success-primary,#16a34a)", fontSize: 12, marginTop: 8 } }, "✅ 密码已保存（其他会话已吊销）| saved, other sessions revoked"));
      if (err) pc.push(h("div", { style: { color: "var(--dsw-alias-state-error-primary,#dc2626)", fontSize: 12, marginTop: 8 } }, "❌ " + err));
      children.push(h("div", { style: V.block }, h("div", { style: { fontWeight: 600, fontSize: 13 } }, "密码重设 | reset password"), pc));

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
