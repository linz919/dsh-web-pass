// dsh-web-pass 门自身页面（登录页 / 首设页）：HTML+CSS 模板与转义。
// v0.3.5 从 proxy.mjs 抽离——纯展示层，零行为变更。
// 注意：这些页面带门的安全头（XFO DENY 等），不参与代理转发。

export function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

// ---- 门页面共享样式（压缩存放：改样式时先展开，提交前压回；行为与展开版一致） ----
const DARK_MODE_CSS = `
<meta name="color-scheme" content="light dark">
<script>(function(){try{var m=matchMedia('(prefers-color-scheme:dark)'),f=function(e){document.documentElement.style.colorScheme=e.matches?'dark':'light';document.body.toggleAttribute('data-dark',e.matches)};f(m);if(m.addEventListener)m.addEventListener('change',f);else m.addListener(f)}catch(e){}}())</script>
<style>
body{--bg:#f7f7f8;--card:#fff;--border:#e5e7eb;--text:#111827;--text2:#6b7280;--input:#fff;--input-border:#d1d5db;--btn-bg:#4f6ef7;--btn-text:#fff;--err:#dc2626;--ok:#16a34a;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:var(--text)}
body[data-dark]{--bg:#1a1a1f;--card:#26262a;--border:#3a3a40;--text:#e5e7eb;--text2:#9ca3af;--input:#1f1f23;--input-border:#4a4a50;--btn-bg:#5f7fff;--btn-text:#fff;--err:#f87171;--ok:#4ade80}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:28px 24px;max-width:360px;width:calc(100% - 48px);text-align:center}
h1{font-size:16px;margin:0 0 4px;color:var(--text)}p{font-size:13px;color:var(--text2);margin:0 0 16px;line-height:1.6}
input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:15px;border:1px solid var(--input-border);border-radius:8px;outline:none;margin-bottom:12px;background:var(--input);color:var(--text)}
input:focus{border-color:#4f6ef7}input:-webkit-autofill{-webkit-box-shadow:0 0 0 1000px var(--input) inset;transition:background-color 999999s}
button{width:100%;padding:10px;font-size:15px;background:var(--btn-bg);color:var(--btn-text);border:none;border-radius:8px;cursor:pointer}
button:disabled{opacity:.55;cursor:default}.err{color:var(--err);font-size:12px;margin-bottom:10px;min-height:16px}
.strength{display:flex;gap:6px;flex-wrap:wrap;justify-content:center;margin-top:-8px;margin-bottom:12px}
.strength span{font-size:11px;padding:2px 6px;border-radius:4px;border:1px solid var(--border);color:var(--text2)}
.strength span.pass{border-color:var(--ok);color:var(--ok)}
</style>`;

export function loginPageHtml(error) {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
${DARK_MODE_CSS}
<title>dsh-web-pass · 登录</title>
</head><body><div class="card">
<h1>🔐 dsh-web-pass</h1>
<p>请输入访问密码 | Please enter the access password</p>
<div class="err">${error ? escapeHtml(String(error)) : ''}</div>
<form method="post" action="/gate-login">
<input name="password" type="password" autocomplete="current-password" autofocus required placeholder="密码 | Password">
<button type="submit">进入 | Enter</button>
</form>
</div></body></html>`;
}

export function setupPageHtml(error) {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
${DARK_MODE_CSS}
<title>dsh-web-pass · 首次设置密码</title>
</head><body><div class="card">
<h1>🔑 首次设置访问密码</h1>
<p>还没有设置访问密码。请先设置一个（≥8 位，含大小写字母和数字），之后每次访问此地址都需要输入。</p>
<div class="err">${error ? escapeHtml(String(error)) : ''}</div>
<form method="post" action="/gate/setup" id="f">
<input name="password" id="pw" type="password" autocomplete="new-password" autofocus required placeholder="新密码" oninput="check()">
<input name="confirm" id="cf" type="password" autocomplete="new-password" required placeholder="确认密码" oninput="check()">
<div class="strength" id="st">
  <span id="s8">≥8位</span><span id="sA">大写</span><span id="sa">小写</span><span id="s1">数字</span>
</div>
<button type="submit" id="btn" disabled>设置密码并进入 | Set &amp; enter</button>
</form>
<script>
function check(){var p=document.getElementById('pw').value,c=document.getElementById('cf').value,ok=p.length>=8&&/[A-Z]/.test(p)&&/[a-z]/.test(p)&&/[0-9]/.test(p)&&c===p&&c.length>0;
document.getElementById('s8').className=p.length>=8?'pass':'';document.getElementById('sA').className=/[A-Z]/.test(p)?'pass':'';
document.getElementById('sa').className=/[a-z]/.test(p)?'pass':'';document.getElementById('s1').className=/[0-9]/.test(p)?'pass':'';
document.getElementById('btn').disabled=!ok}
</script>
</div></body></html>`;
}
