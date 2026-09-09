// dsh-web-pass 核心：Host/Origin 改写反向代理 + 会话令牌认证 + 暗色主题
// 密码用 scrypt 哈希、cookie 存会话令牌（≠密码）、密码强度 ≥8 位+大小写+数字

import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';
import { connect as netConnect } from 'node:net';

const DEFAULT_UPSTREAM = { host: '127.0.0.1', port: 3080 };

const RANDOM_UUID_POLYFILL = `<script data-dsh-gate-polyfill="1">!function(){try{if(self.crypto&&!self.crypto.randomUUID){self.crypto.randomUUID=function(){var b=new Uint8Array(16);self.crypto.getRandomValues(b);b[6]=b[6]&15|64;b[8]=b[8]&63|128;var h="";for(var i=0;i<16;i++){var x=b[i].toString(16);h+=(x.length<2?"0":"")+x;if(i===3||i===5||i===7||i===9)h+="-";}return h;}}}catch(e){}}();</script>`;
export const DEFAULT_INJECT = RANDOM_UUID_POLYFILL;

// 退出浮标：注入非管理员条目的 HTML 页（访客/工具间没有设置页，需要 door 上的退出按钮）
const LOGOUT_CHIP_HTML = `<style id="dsh-gate-logout-style">#dsh-gate-logout{position:fixed;right:12px;bottom:12px;z-index:2147483647;font:12px/1.4 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:7px 12px;border-radius:999px;border:1px solid rgba(128,128,128,.45);background:rgba(127,127,127,.14);color:inherit;opacity:.55;transition:opacity .2s;text-decoration:none;backdrop-filter:blur(4px)}#dsh-gate-logout:hover{opacity:1}</style><a id="dsh-gate-logout" href="/gate/logout" title="退出密码门会话 | exit gate session" rel="noreferrer">🚪 退出</a>`;

export const SESSION_COOKIE = 'dws_session';
const SESSION_MAX_AGE = 172800; // 2 天（与服务端 SESSION_TTL_MS 对齐；滑动续期时重下）

/** TCP 探活（上游状态灯/登录前检查用）：通 true，不通 false，绝不抛错。 */
export function probeTcp(host, port, timeoutMs = 1200) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (ok) => { if (!done) { done = true; try { sock.destroy(); } catch {} resolve(ok); } };
    let sock;
    try {
      sock = netConnect({ host, port });
    } catch { resolve(false); return; }
    const timer = setTimeout(() => finish(false), Math.max(200, Number(timeoutMs) || 1200));
    sock.once('connect', () => { clearTimeout(timer); finish(true); });
    sock.once('error', () => { clearTimeout(timer); finish(false); });
  });
}

// ---- 非 loopback 页面解锁 Host 设置（v0.3.1 新增）----
// DSH 客户端只认 localhost/127.x/[::1] 为 loopback；经本 gate（LAN IP / 公网域名）
// 访问时，设置一律降级为 memory 模式——设置里的 插件配置/模型/常规 等标签页整页空白。
// 这里只对 client-connection 模块做定向改写，把该判定补为恒真：浏览器地址不变、
// 密码门仍是唯一入口。配置 clientHostTrust: false 可关闭。
const REWRITE_MODULE_MARK = '@deepseek-ai/dsh-client-connection/client.js';
const REWRITE_ANCHOR = 'isLoopbackHostname(pageLocation.hostname)';

// ---- 安全辅助 ----
function isHttps(req) {
  const proto = String(req.headers['x-forwarded-proto'] ?? '').toLowerCase();
  return proto === 'https' || req.socket?.encrypted === true;
}
function securityHeaders() {
  return {
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'x-robots-tag': 'noindex, nofollow',
  };
}
function sessionCookie(token, maxAge, req) {
  let c = `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
  if (isHttps(req)) c += '; Secure';
  return c;
}
function clearSessionCookie(req) {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0` + (isHttps(req) ? '; Secure' : '');
}

export function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

// ---- 暗色模式 CSS 基础变量 ----
const DARK_MODE_CSS = `
<meta name="color-scheme" content="light dark">
<script>(function(){
var d=window.matchMedia&&window.matchMedia('(prefers-color-scheme:dark)').matches;
if(d)document.documentElement.style.colorScheme='dark',document.body.setAttribute('data-dark','');
var mq=window.matchMedia('(prefers-color-scheme:dark)');
if(mq){var fn=function(e){if(e.matches){document.documentElement.style.colorScheme='dark';document.body.setAttribute('data-dark','')}else{document.documentElement.style.colorScheme='light';document.body.removeAttribute('data-dark')}};if(mq.addEventListener)mq.addEventListener('change',fn);else mq.addListener(fn)}
})()</script>
<style>
body{--bg:#f7f7f8;--card:#fff;--border:#e5e7eb;--text:#111827;--text2:#6b7280;--input:#fff;--input-border:#d1d5db;--btn-bg:#4f6ef7;--btn-text:#fff;--err:#dc2626;--ok:#16a34a}
body[data-dark]{--bg:#1a1a1f;--card:#26262a;--border:#3a3a40;--text:#e5e7eb;--text2:#9ca3af;--input:#1f1f23;--input-border:#4a4a50;--btn-bg:#5f7fff;--btn-text:#fff;--err:#f87171;--ok:#4ade80}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:var(--text)}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:28px 24px;max-width:360px;width:calc(100% - 48px);text-align:center}
h1{font-size:16px;margin:0 0 4px;color:var(--text)}
p{font-size:13px;color:var(--text2);margin:0 0 16px;line-height:1.6}
input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:15px;border:1px solid var(--input-border);border-radius:8px;outline:none;margin-bottom:12px;background:var(--input);color:var(--text)}
input:focus{border-color:#4f6ef7}
input:-webkit-autofill{-webkit-box-shadow:0 0 0 1000px var(--input) inset;transition:background-color 999999s}
button{width:100%;padding:10px;font-size:15px;background:var(--btn-bg);color:var(--btn-text);border:none;border-radius:8px;cursor:pointer}
button:disabled{opacity:.55;cursor:default}
.err{color:var(--err);font-size:12px;margin-bottom:10px;min-height:16px}
.strength{display:flex;gap:6px;flex-wrap:wrap;justify-content:center;margin-top:-8px;margin-bottom:12px}
.strength span{font-size:11px;padding:2px 6px;border-radius:4px;border:1px solid var(--border);color:var(--text2)}
.strength span.pass{border-color:var(--ok);color:var(--ok)}
</style>`;

// ---- 密码强度校验 ----
function passwordStrength(p) {
  if (typeof p !== 'string' || p.length < 8) return { ok: false, reason: '密码至少需要 8 位' };
  if (!/[a-z]/.test(p)) return { ok: false, reason: '密码必须包含小写字母' };
  if (!/[A-Z]/.test(p)) return { ok: false, reason: '密码必须包含大写字母' };
  if (!/[0-9]/.test(p)) return { ok: false, reason: '密码必须包含数字' };
  return { ok: true, reason: null };
}

function loginPageHtml(error) {
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

function setupPageHtml(error) {
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
function check(){
  var p=document.getElementById('pw').value,c=document.getElementById('cf').value;
  var ok=p.length>=8&&/[A-Z]/.test(p)&&/[a-z]/.test(p)&&/[0-9]/.test(p)&&c===p&&c.length>0;
  document.getElementById('s8').className=p.length>=8?'pass':'';
  document.getElementById('sA').className=/[A-Z]/.test(p)?'pass':'';
  document.getElementById('sa').className=/[a-z]/.test(p)?'pass':'';
  document.getElementById('s1').className=/[0-9]/.test(p)?'pass':'';
  document.getElementById('btn').disabled=!ok;
}
</script>
</div></body></html>`;
}

function isHtmlRequest(req) {
  const accept = String(req.headers.accept ?? '');
  return accept.includes('text/html') || req.url === '/' || /\.html?$/i.test(String(req.url));
}

function loopbackAuthority(headers, upstream) {
  const authority = `${upstream.host}:${upstream.port}`;
  headers.Host = authority;
  if (headers.origin) headers.origin = `http://${authority}`;
  if (headers.Origin) headers.Origin = `http://${authority}`;
  return headers;
}

export function createGateProxy({ port = 3081, host = '0.0.0.0', upstream = DEFAULT_UPSTREAM, upstreams = null, log = null, injectHtml = DEFAULT_INJECT, auth = null, maxLoginAttempts = 3, loginLockMs = 60_000, onAccess = null, trustProxy = false, dshAuth = null, getDshAuth = null, getUpstreams = null, clientHostTrust = true } = {}) {
  // 多上游：upstreams 为 [{host, port, clientHostTrust}]，按会话条目分流；
  // 老调用只传 upstream/dshAuth 时自动包一层（向后兼容）。
  const routes = Array.isArray(upstreams) && upstreams.length > 0
    ? upstreams
    : [{ host: upstream.host, port: upstream.port, clientHostTrust }];
  const dshAuthOf = typeof getDshAuth === 'function' ? getDshAuth : (() => dshAuth);
  // 动态条目表：getUpstreams 提供时每次取最新（设置页新增行即时参与分流），
  // 否则用启动时静态表。
  const routesOf = typeof getUpstreams === 'function' ? getUpstreams : () => routes;
  const routeOf = (entry) => { const list = routesOf(); return list[entry] ?? list[0]; };
  // 登录失败计数（防爆破，per-IP 滑动窗口）
  const failuresByIp = new Map();
  // 锁定窗口取自配置（loginLockMs），下限 1s 防误配
  const RATE_WINDOW_MS = Math.max(1000, Number(loginLockMs) || 60_000);
  // 失败计数表上限：防止（伪造）海量 key 撑爆内存，超限先淘汰最早记录
  const FAILURE_MAP_MAX = 10_000;
  function failKey(req) {
    if (!trustProxy) return req.socket?.remoteAddress ?? '?'; // 默认只信 socket 直连地址，XFF 可伪造
    const xff = String(req.headers['x-forwarded-for'] ?? '').split(',')[0]?.trim();
    // 截断到 64 字符（任何 IP 文本都够用），防止超长 XFF 头作为 Map key 撑内存
    return (xff && xff !== 'unknown') ? xff.slice(0, 64) : (req.socket?.remoteAddress ?? '?');
  }
  function isRateLimited(ip) {
    if (!ip) return false;
    const now = Date.now();
    const arr = (failuresByIp.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
    if (arr.length >= maxLoginAttempts) { failuresByIp.set(ip, arr); return true; }
    return false;
  }
  function recordFailure(ip) {
    if (!ip) return;
    while (failuresByIp.size >= FAILURE_MAP_MAX) { // 简单 FIFO 淘汰，防内存膨胀
      const first = failuresByIp.keys().next().value;
      if (first === undefined) break;
      failuresByIp.delete(first);
    }
    const now = Date.now();
    const arr = (failuresByIp.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
    arr.push(now);
    failuresByIp.set(ip, arr);
  }
  function clearFailures(ip) { failuresByIp.delete(ip); }

  // 滑动续期：服务端刚续了有效期就顺手重下浏览器 cookie（否则浏览器侧先过期）。
  // 只做追加合并，不覆盖上游自带的 Set-Cookie。
  function attachSessionRefresh(res, req, token) {
    const orig = res.writeHead;
    res.writeHead = function () {
      const args = [...arguments];
      try {
        const c = sessionCookie(token, SESSION_MAX_AGE, req);
        let headers = null;
        for (let k = 1; k < args.length; k++) {
          const a = args[k];
          if (a && typeof a === 'object' && !Array.isArray(a)) { headers = a; break; }
        }
        if (!headers) { headers = {}; args.push(headers); }
        const prev = headers['set-cookie'];
        headers['set-cookie'] = prev === undefined ? [c] : (Array.isArray(prev) ? [...prev, c] : [prev, c]);
      } catch {}
      return orig.apply(res, args);
    };
  }

  const server = createServer(async (req, res) => {
    if (onAccess) {
      res.on('finish', () => { try { onAccess(req, res); } catch {} });
    }
    // 所有响应都带安全头
    const hdrs = securityHeaders();
    for (const [k, v] of Object.entries(hdrs)) res.setHeader(k, v);
    try {
      if (!auth) { const r0 = routeOf(0); await proxyForward(req, res, { upstream: r0, injectHtml, dshAuth: dshAuthOf(0), clientHostTrust: r0.clientHostTrust !== false }); return; }

      const hasPassword = typeof auth.hasAnyPassword === 'function' ? auth.hasAnyPassword() : !!auth.getPasswordSource();
      const sessionToken = parseCookies(req.headers.cookie)[SESSION_COOKIE];
      const sessRaw = hasPassword ? auth.verifySession(sessionToken) : null;
      // 兼容旧版布尔返回：true 视为管理员条目未续期
      const sess = sessRaw && typeof sessRaw === 'object' ? sessRaw : (sessRaw ? { entry: 0, renewed: false } : null);
      const authed = !!sess;
      if (sess?.renewed) attachSessionRefresh(res, req, sessionToken);

      // ---- 尚未设置密码：强制先设置 ----
      if (!hasPassword) {
        if (req.method === 'POST' && req.url === '/gate/setup') {
          let body = '';
          req.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
          req.on('end', async () => {
            const params = new URLSearchParams(body);
            const pw = String(params.get('password') ?? '').trim();
            const confirm = String(params.get('confirm') ?? '').trim();
            let err = null;
            if (!pw) err = '密码不能为空';
            else { const st = passwordStrength(pw); if (!st.ok) err = st.reason; }
            if (!err && !confirm) err = '请再次输入确认密码';
            if (!err && pw !== confirm) err = '两次输入的密码不一致';
            if (err) { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); res.end(setupPageHtml(err)); return; }
            try {
              if (auth.setPasswordHash.length >= 2) await auth.setPasswordHash(0, pw);
              else await auth.setPasswordHash(pw); // 兼容旧版单密码 auth
              const tok = auth.createSession(0);
              res.writeHead(302, { location: '/', 'set-cookie': sessionCookie(tok, SESSION_MAX_AGE, req), 'cache-control': 'no-store' });
              res.end();
            } catch (e) {
              res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
              res.end(setupPageHtml('保存失败：' + (e.message || String(e))));
            }
          });
          return;
        }
        if (req.method === 'GET' && req.url === '/gate-setup') {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
          res.end(setupPageHtml(false));
          return;
        }
        res.writeHead(302, { location: '/gate-setup' }); res.end(); return;
      }

      // ---- 登录（单密码框按顺序试各条目；报错保持笼统，不透露哪条）----
      if (req.method === 'POST' && req.url === '/gate-login') {
        const ip = failKey(req);
        if (isRateLimited(ip)) { res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': String(Math.ceil(RATE_WINDOW_MS / 1000)) }); res.end(loginPageHtml(`尝试次数过多，请 ${Math.ceil(RATE_WINDOW_MS / 1000)} 秒后重试`)); return; }
        let body = '';
        req.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
        req.on('end', () => {
          // 注意：不使用 async，直接用 .then() 链，确保错误不逃逸为 unhandled rejection
          const submitted = String(new URLSearchParams(body).get('password') ?? '');
          const matchEntry = async () => {
            if (typeof auth.verifyAny === 'function') return auth.verifyAny(submitted);
            try { return (await auth.verify(submitted)) ? 0 : -1; } catch { return -1; }
          };
          matchEntry().then(async (idx) => {
            if (!Number.isInteger(idx) || idx < 0) {
              recordFailure(ip);
              res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
              res.end(loginPageHtml('密码错误，请重试'));
              return;
            }
            // 上游探活：不通则提示未启用（访客没起来只影响访客，主人照常用）
            const up = routeOf(idx);
            let upOk = true;
            try { upOk = await probeTcp(up.host, up.port, 1200); } catch { upOk = false; }
            if (!upOk) {
              res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
              res.end(loginPageHtml('该入口暂未启用，请稍后再试'));
              return;
            }
            clearFailures(ip);
            const tok = auth.createSession(idx);
            res.writeHead(302, { location: '/', 'set-cookie': sessionCookie(tok, SESSION_MAX_AGE, req), 'cache-control': 'no-store' });
            res.end();
          }).catch((e) => {
            // auth.verify 抛异常（如 scrypt 解析错误）：记录错误，显示友好提示，不崩溃进程
            recordFailure(ip);
            try { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); } catch {}
            try { res.end(loginPageHtml('密码验证异常，请重试')); } catch {}
          });
        });
        return;
      }

      // ---- 登出（POST/GET 皆可：设置页按钮用 POST，浮标/手动地址用 GET）----
      if ((req.method === 'POST' || req.method === 'GET') && req.url === '/gate/logout') {
        if (sessionToken) auth.destroySession(sessionToken);
        res.writeHead(302, { location: '/gate-login', 'set-cookie': clearSessionCookie(req), 'cache-control': 'no-store' });
        res.end(); return;
      }

      // ---- 未认证 → 登录页（GET 直接给页面，不重定向）----
      if (!authed) {
        // GET /gate-login → 直接给登录页（不能重定向到自己！）
        if (req.method === 'GET' && req.url === '/gate-login') {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
          res.end(loginPageHtml(false));
          return;
        }
        if (isHtmlRequest(req)) {
          res.writeHead(302, { location: '/gate-login' }); res.end();
        } else {
          res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.end('{"error":"unauthorized"}');
        }
        return;
      }

      // ---- 已认证：日志查看器仅管理员条目可用；其余按会话条目代理到各自上游 ----
      if (req.url && req.url.startsWith('/dsh-logs/')) {
        if (!sess || sess.entry !== 0) {
          res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
          res.end('forbidden');
          return;
        }
        const logHeaders = { ...req.headers };
        const logReq = httpRequest({ host: '127.0.0.1', port: 3082, method: req.method, path: req.url.replace('/dsh-logs/', '/'), headers: logHeaders, agent: false }, (logRes) => {
          res.writeHead(logRes.statusCode ?? 502, logRes.headers);
          logRes.pipe(res);
        });
        logReq.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('dsh-web-pass: logs upstream error'); });
        req.pipe(logReq);
        return;
      }

      // ---- 已认证：代理到会话条目对应的上游（非管理员条目注入退出浮标）----
      const up = routeOf(sess?.entry ?? 0);
      await proxyForward(req, res, { upstream: up, injectHtml, dshAuth: dshAuthOf(sess?.entry ?? 0), clientHostTrust: up.clientHostTrust !== false, logoutChip: (sess?.entry ?? 0) !== 0 });
    } catch (e) {
      if (!res.headersSent) { res.writeHead(500); res.end('internal error'); }
    }
  });

  // WebSocket upgrade（按会话条目分流；DSH 代持按条目注入，非 DSH 上游跳过）
  server.on('upgrade', async (req, socket, head) => {
    let entry = 0;
    if (auth) {
      const sessionToken = parseCookies(req.headers.cookie)[SESSION_COOKIE];
      const r = auth.verifySession(sessionToken);
      const s = r && typeof r === 'object' ? r : (r ? { entry: 0, renewed: false } : null);
      if (!s) { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); socket.destroy(); return; }
      entry = s.entry ?? 0;
    }
    const up = routeOf(entry);
    const headers = loopbackAuthority({ ...req.headers }, up);
    // 代持 DSH 内置认证：WebSocket 握手同样注入 DSH cookie
    try {
      const da = dshAuthOf(entry);
      if (da) {
        const dshCookie = await da.get();
        if (dshCookie) headers.cookie = dshCookie;
      }
    } catch { /* 代持失败不阻断握手 */ }
    const proxyReq = httpRequest({ host: up.host, port: up.port, method: req.method, path: req.url, headers, agent: false });
    proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
      socket.write('HTTP/1.1 101 Switching Protocols\r\n');
      const raw = [];
      for (const [k, v] of Object.entries(proxyRes.headers)) raw.push(`${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
      socket.write(`${raw.join('\r\n')}\r\n\r\n`);
      if (proxyHead?.length) socket.write(proxyHead);
      proxySocket.pipe(socket); socket.pipe(proxySocket);
      const teardown = () => { try { proxySocket.destroy(); } catch {} try { socket.destroy(); } catch {} };
      proxySocket.on('close', teardown); socket.on('close', teardown);
    });
    proxyReq.on('response', (proxyRes) => {
      if (proxyRes.statusCode === 101) return;
      try {
        const raw = [`HTTP/1.1 ${proxyRes.statusCode} ${proxyRes.statusMessage ?? ''}`.trim()];
        for (const [k, v] of Object.entries(proxyRes.headers)) raw.push(`${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
        socket.end(raw.join('\r\n') + '\r\n\r\n');
        proxyRes.resume();
      } catch { socket.destroy(); }
    });
    proxyReq.on('error', () => socket.destroy());
    if (head?.length) proxyReq.write(head);
    proxyReq.end();
    socket.on('error', () => socket.destroy());
  });

  const clientSockets = new Set();
  server.on('connection', (sock) => { clientSockets.add(sock); sock.on('close', () => clientSockets.delete(sock)); sock.on('error', () => {}); });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      resolve({ server, port: server.address().port, close: () => new Promise((r) => { for (const s of clientSockets) { try { s.destroy(); } catch {} } server.close(() => r()); }) });
    });
  });
}

async function proxyForward(req, res, { upstream, injectHtml, dshAuth, clientHostTrust = true, logoutChip = false } = {}) {
  const up = upstream ?? DEFAULT_UPSTREAM;
  const headers = loopbackAuthority({ ...req.headers }, up);
  // 代持 DSH 内置认证：注入进程内换取的 DSH cookie，浏览器无需 token/cookie
  try {
    if (dshAuth) {
      const dshCookie = await dshAuth.get();
      if (dshCookie) headers.cookie = dshCookie;
    }
  } catch { /* 代持失败不阻断传输，DSH 会以 401 兜底 */ }
  // 不转发压缩协商：上游以明文回（nginx 等默认开 gzip 会跳过注入分支——
  // polyfill/模块改写/退出浮标全依赖明文），压缩交给门前的反向代理做。
  delete headers['accept-encoding'];
  const proxyReq = httpRequest({ host: up.host, port: up.port, method: req.method, path: req.url, headers, agent: false }, (proxyRes) => {
    const contentType = String(proxyRes.headers['content-type'] ?? '');
    const isCompressed = /gzip|br|deflate/i.test(String(proxyRes.headers['content-encoding'] ?? ''));
    // 注入 UUID polyfill（非安全上下文 HTTP 需要）+ 退出浮标（非管理员条目）
    if ((injectHtml || logoutChip) && contentType.includes('text/html') && !isCompressed) {
      const chunks = [];
      proxyRes.on('data', (c) => chunks.push(c));
      proxyRes.on('end', () => {
        let html = Buffer.concat(chunks).toString('utf8');
        if (injectHtml && !html.includes('data-dsh-gate-polyfill')) html = html.replace(/<head[^>]*>/i, (m) => `${m}${DEFAULT_INJECT}`);
        if (logoutChip && !html.includes('dsh-gate-logout')) {
          // 优先插在 <body> 开头（fixed 定位不受插入点影响）；无 body 标签则放弃（非标准页）
          if (/<body[^>]*>/i.test(html)) html = html.replace(/<body[^>]*>/i, (m) => `${m}${LOGOUT_CHIP_HTML}`);
        }
        const out = Buffer.from(html, 'utf8');
        const outHeaders = { ...proxyRes.headers };
        delete outHeaders['content-length']; delete outHeaders['transfer-encoding'];
        outHeaders['content-length'] = String(out.length);
        res.writeHead(proxyRes.statusCode ?? 200, outHeaders);
        res.end(out);
      });
      proxyRes.on('error', () => res.destroy());
      return;
    }
    // 定向改写 client-connection 模块（见文件头「非 loopback 页面解锁 Host 设置」注释）
    if (clientHostTrust && !isCompressed
      && contentType.includes('javascript')
      && String(req.url ?? '').includes(REWRITE_MODULE_MARK)) {
      const chunks = [];
      proxyRes.on('data', (c) => chunks.push(c));
      proxyRes.on('end', () => {
        let js = Buffer.concat(chunks).toString('utf8');
        if (js.includes(REWRITE_ANCHOR)) {
          js = js.replace(REWRITE_ANCHOR, `(${REWRITE_ANCHOR} || !0)`);
          console.info('dsh-web-pass: 已改写 client-connection 模块（非 loopback 页面启用 host 设置模式）');
        } else {
          console.warn('dsh-web-pass: 未找到 isLoopback 锚点，模块原样透传（DSH 版本可能已更新，请同步更新 REWRITE_ANCHOR）');
        }
        const out = Buffer.from(js, 'utf8');
        const outHeaders = { ...proxyRes.headers };
        delete outHeaders['content-length']; delete outHeaders['transfer-encoding'];
        delete outHeaders.etag; delete outHeaders['last-modified'];
        outHeaders['content-length'] = String(out.length);
        outHeaders['cache-control'] = 'no-cache';
        res.writeHead(proxyRes.statusCode ?? 200, outHeaders);
        res.end(out);
      });
      proxyRes.on('error', () => res.destroy());
      return;
    }
    // 响应原样透传（压缩交给前端反向代理做）
    res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
    proxyRes.pipe(res);
    res.on('close', () => proxyRes.destroy());
    proxyRes.on('error', () => res.destroy());
  });
  proxyReq.on('error', (err) => {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`dsh-web-pass: 无法连接上游（${up.host}:${up.port}）| ${err.message}`);
  });
  req.pipe(proxyReq);
}
