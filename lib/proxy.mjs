// dsh-web-pass 核心：Host/Origin 改写反向代理 + 会话令牌认证 + 暗色主题
// 密码用 scrypt 哈希、cookie 存会话令牌（≠密码）、密码强度 ≥8 位+大小写+数字

import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';

const DEFAULT_UPSTREAM = { host: '127.0.0.1', port: 3080 };

const RANDOM_UUID_POLYFILL = `<script data-dsh-gate-polyfill="1">!function(){try{if(self.crypto&&!self.crypto.randomUUID){self.crypto.randomUUID=function(){var b=new Uint8Array(16);self.crypto.getRandomValues(b);b[6]=b[6]&15|64;b[8]=b[8]&63|128;var h="";for(var i=0;i<16;i++){var x=b[i].toString(16);h+=(x.length<2?"0":"")+x;if(i===3||i===5||i===7||i===9)h+="-";}return h;}}}catch(e){}}();</script>`;
export const DEFAULT_INJECT = RANDOM_UUID_POLYFILL;

const SESSION_COOKIE = 'dws_session';
const SESSION_MAX_AGE = 86400; // 24h

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

function parseCookies(header) {
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
<p>请输入访问密码 | Enter the password</p>
<div class="err">${error ? escapeHtml(String(error)) : ''}</div>
<form method="post" action="/gate-login">
<input name="password" type="password" autocomplete="current-password" autofocus required placeholder="密码">
<button type="submit">登录 | Login</button>
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

export function createGateProxy({ port = 3081, host = '0.0.0.0', upstream = DEFAULT_UPSTREAM, log = null, injectHtml = DEFAULT_INJECT, auth = null, maxLoginAttempts = 3, loginLockMs = 60_000, onAccess = null, trustProxy = false } = {}) {
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

  const server = createServer(async (req, res) => {
    if (onAccess) {
      res.on('finish', () => { try { onAccess(req, res); } catch {} });
    }
    // 所有响应都带安全头
    const hdrs = securityHeaders();
    for (const [k, v] of Object.entries(hdrs)) res.setHeader(k, v);
    try {
      if (!auth) return proxyForward(req, res, upstream, injectHtml);

      const hasPassword = !!auth.getPasswordSource();
      const sessionToken = parseCookies(req.headers.cookie)[SESSION_COOKIE];
      const authed = hasPassword ? auth.verifySession(sessionToken) : false;

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
              await auth.setPasswordHash(pw);
              const tok = auth.createSession();
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

      // ---- 登录 ----
      if (req.method === 'POST' && req.url === '/gate-login') {
        const ip = failKey(req);
        if (isRateLimited(ip)) { res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': String(Math.ceil(RATE_WINDOW_MS / 1000)) }); res.end(loginPageHtml(`尝试次数过多，请 ${Math.ceil(RATE_WINDOW_MS / 1000)} 秒后重试`)); return; }
        let body = '';
        req.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
        req.on('end', () => {
          // 注意：不使用 async，直接用 .then() 链，确保错误不逃逸为 unhandled rejection
          const submitted = String(new URLSearchParams(body).get('password') ?? '');
          auth.verify(submitted).then((ok) => {
            if (ok) {
              clearFailures(ip);
              const tok = auth.createSession();
              res.writeHead(302, { location: '/', 'set-cookie': sessionCookie(tok, SESSION_MAX_AGE, req), 'cache-control': 'no-store' });
              res.end();
            } else {
              recordFailure(ip);
              res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
              res.end(loginPageHtml('密码错误，请重试'));
            }
          }).catch((e) => {
            // auth.verify 抛异常（如 scrypt 解析错误）：记录错误，显示友好提示，不崩溃进程
            recordFailure(ip);
            try { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); } catch {}
            try { res.end(loginPageHtml('密码验证异常，请重试')); } catch {}
          });
        });
        return;
      }

      // ---- 登出 ----
      if (req.method === 'POST' && req.url === '/gate/logout') {
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

      // ---- 已认证：/dsh-logs/ → 内嵌日志查看器（3082）----
      if (req.url && req.url.startsWith('/dsh-logs/')) {
        const logHeaders = { ...req.headers };
        const logReq = httpRequest({ host: '127.0.0.1', port: 3082, method: req.method, path: req.url.replace('/dsh-logs/', '/'), headers: logHeaders, agent: false }, (logRes) => {
          res.writeHead(logRes.statusCode ?? 502, logRes.headers);
          logRes.pipe(res);
        });
        logReq.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('dsh-web-pass: logs upstream error'); });
        req.pipe(logReq);
        return;
      }

      // ---- 已认证：代理到上游 ----
      proxyForward(req, res, upstream, injectHtml);
    } catch (e) {
      if (!res.headersSent) { res.writeHead(500); res.end('internal error'); }
    }
  });

  // WebSocket upgrade
  server.on('upgrade', (req, socket, head) => {
    if (auth) {
      const sessionToken = parseCookies(req.headers.cookie)[SESSION_COOKIE];
      if (!auth.verifySession(sessionToken)) { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); socket.destroy(); return; }
    }
    const headers = loopbackAuthority({ ...req.headers }, upstream);
    const proxyReq = httpRequest({ host: upstream.host, port: upstream.port, method: req.method, path: req.url, headers, agent: false });
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

function proxyForward(req, res, upstream, injectHtml) {
  const headers = loopbackAuthority({ ...req.headers }, upstream);
  const proxyReq = httpRequest({ host: upstream.host, port: upstream.port, method: req.method, path: req.url, headers, agent: false }, (proxyRes) => {
    const contentType = String(proxyRes.headers['content-type'] ?? '');
    const isCompressed = /gzip|br|deflate/i.test(String(proxyRes.headers['content-encoding'] ?? ''));
    // 注入 UUID polyfill（非安全上下文 HTTP 需要）
    if (injectHtml && contentType.includes('text/html') && !isCompressed) {
      const chunks = [];
      proxyRes.on('data', (c) => chunks.push(c));
      proxyRes.on('end', () => {
        let html = Buffer.concat(chunks).toString('utf8');
        if (!html.includes('data-dsh-gate-polyfill')) html = html.replace(/<head[^>]*>/i, (m) => `${m}${DEFAULT_INJECT}`);
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
    // 响应原样透传（压缩交给前端反向代理做）
    res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
    proxyRes.pipe(res);
    res.on('close', () => proxyRes.destroy());
    proxyRes.on('error', () => res.destroy());
  });
  proxyReq.on('error', (err) => {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`dsh-web-pass: 无法连接上游 dsh web（${upstream.host}:${upstream.port}）| ${err.message}`);
  });
  req.pipe(proxyReq);
}
