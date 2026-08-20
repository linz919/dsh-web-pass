// dsh-web-pass 核心：Host/Origin 改写反向代理 + cookie 密码认证
//
// 为什么需要它：DSH 的 /api 浏览器信任栅栏只认 loopback（127.0.0.1）或
// --trusted-host 白名单。本代理把入站 Host/Origin 统一改写成 loopback 权威
// （127.0.0.1:3080），转发给本机 dsh web——栅栏永远看到 loopback，于是不需要
// 改 dsh 的任何配置。认证用 cookie（不是 Basic Auth），手机上持久化，不会反复弹框。
//
// 与 dsh-pocket 的区别：我们去掉了 cloudflared 公网隧道，只保留局域网代理 +
// 设置页可改密码 + 网关访问日志（不留公网隧道，也不注入移动端布局）。

import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';

const DEFAULT_UPSTREAM = { host: '127.0.0.1', port: 3080 };

// 非安全上下文（http://<LAN-IP>:端口）里浏览器没有 crypto.randomUUID，
// DSH 连接层会抛错。代理给 HTML 注入 polyfill（只在缺少时生效）。
const RANDOM_UUID_POLYFILL = `<script data-dsh-gate-polyfill="1">!function(){try{if(self.crypto&&!self.crypto.randomUUID){self.crypto.randomUUID=function(){var b=new Uint8Array(16);self.crypto.getRandomValues(b);b[6]=b[6]&15|64;b[8]=b[8]&63|128;var h="";for(var i=0;i<16;i++){var x=b[i].toString(16);h+=(x.length<2?"0":"")+x;if(i===3||i===5||i===7||i===9)h+="-";}return h;}}}catch(e){}}();</script>`;
const INJECT_MARK = 'data-dsh-gate-polyfill="1"';
// 只注入 randomUUID polyfill（移动端布局已移除）。
export const DEFAULT_INJECT = RANDOM_UUID_POLYFILL;

const TOKEN_COOKIE = 'dsh_gate_token';

function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

function loginPageHtml(error) {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DSH Gate · 访问验证</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px 24px;max-width:320px;width:calc(100% - 48px);text-align:center}
h1{font-size:16px;margin:0 0 4px;color:#111827}
p{font-size:13px;color:#6b7280;margin:0 0 16px}
input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:18px;letter-spacing:6px;text-align:center;border:1px solid #d1d5db;border-radius:8px;outline:none;margin-bottom:12px}
input:focus{border-color:#4f6ef7}
button{width:100%;padding:10px;font-size:15px;background:#4f6ef7;color:#fff;border:none;border-radius:8px;cursor:pointer}
.err{color:#dc2626;font-size:12px;margin-bottom:10px;min-height:16px}
</style></head><body><div class="card">
<h1>🔐 DSH Gate</h1>
<p>此地址受访问密码保护，请输入密码 | password-protected — enter the password</p>
<div class="err">${error ? escapeHtml(String(error)) : ''}</div>
<form method="post" action="/gate-login">
<input name="token" type="password" inputmode="text" maxlength="64" autocomplete="one-time-code" autofocus required>
<button type="submit">进入 | Enter</button>
</form>
</div></body></html>`;
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

// 首次访问（尚未设置密码）时强制先设密码。
function setupPageHtml(error) {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DSH Gate · 首次设置密码</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px 24px;max-width:340px;width:calc(100% - 48px);text-align:center}
h1{font-size:16px;margin:0 0 6px;color:#111827}
p{font-size:13px;color:#6b7280;margin:0 0 16px;line-height:1.6;text-align:left}
input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:15px;border:1px solid #d1d5db;border-radius:8px;outline:none;margin-bottom:12px}
input:focus{border-color:#4f6ef7}
button{width:100%;padding:10px;font-size:15px;background:#4f6ef7;color:#fff;border:none;border-radius:8px;cursor:pointer}
.err{color:#dc2626;font-size:12px;margin-bottom:10px;min-height:16px}
</style></head><body><div class="card">
<h1>🔑 首次设置访问密码</h1>
<p>还没有设置访问密码。请先设置一个，之后访问此地址都需要输入。<br>要求：不能是纯数字（至少含字母）。</p>
<div class="err">${error ? escapeHtml(String(error)) : ''}</div>
<form method="post" action="/gate/setup">
<input name="password" type="password" inputmode="text" maxlength="64" autocomplete="new-password" autofocus required placeholder="输入访问密码">
<input name="confirm" type="password" inputmode="text" maxlength="64" autocomplete="new-password" required placeholder="再次输入访问密码（确认）">
<button type="submit">设置密码并进入 | Set &amp; enter</button>
</form>
</div></body></html>`;
}

function adminPageHtml(lanUrl, hasPassword) {
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DSH Gate · 管理</title>
<style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f3f4f6;padding:24px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:20px;max-width:420px;margin:0 auto}
h1{font-size:16px;margin:0 0 12px}
.row{margin:12px 0}
label{font-size:13px;color:#374151;display:block;margin-bottom:6px}
input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:15px;border:1px solid #d1d5db;border-radius:8px;outline:none}
input:focus{border-color:#4f6ef7}
button{margin-top:10px;padding:9px 16px;font-size:14px;background:#4f6ef7;color:#fff;border:none;border-radius:8px;cursor:pointer}
.code{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all;background:#f3f4f6;padding:8px;border-radius:6px}
</style></head><body><div class="card">
<h1>🔐 DSH Gate 管理</h1>
<div class="row"><label>局域网访问地址</label><div class="code">${lanUrl ?? '(代理未就绪)'}</div></div>
<div class="row"><label>当前密码</label><div class="code">${hasPassword ? '已设置（出于安全不显示明文）' : '未设置（任何人都可访问，请尽快设置）'}</div></div>
<form method="post" action="/gate/api/password">
<div class="row"><label>设置新密码（留空不变更）</label><input name="password" type="text" autocomplete="off" placeholder="任意字符串，例如 12345678"></div>
<button type="submit">保存密码 | Save</button>
</form>
<div class="row" style="font-size:12px;color:#6b7280">提示：也可在 DSH 设置页「手机访问」里改密码。</div>
</div></body></html>`;
}

function isHtmlRequest(req) {
  const accept = String(req.headers.accept ?? '');
  return accept.includes('text/html') || req.url === '/' || /\.html?$/i.test(String(req.url));
}

function authCheck(req, token) {
  if (!token) return true;
  const cookieTok = parseCookies(req.headers.cookie)[TOKEN_COOKIE];
  if (cookieTok === token) return true;
  const qTok = new URL(req.url ?? '/', 'http://x').searchParams.get('token');
  return qTok === token;
}

function loopbackAuthority(headers, upstream) {
  const authority = `${upstream.host}:${upstream.port}`;
  headers.Host = authority;
  if (headers.origin) headers.origin = `http://${authority}`;
  if (headers.Origin) headers.Origin = `http://${authority}`;
  return headers;
}

export function createGateProxy({ port = 3081, host = '0.0.0.0', upstream = DEFAULT_UPSTREAM, log = null, injectHtml = DEFAULT_INJECT, auth = null, onSetPassword = null, maxLoginAttempts = 3, loginLockMs = 60_000, onAccess = null } = {}) {
  // 登录失败计数（防爆破）。注意：所有外部流量都经反向代理进来，remoteAddress 通常都是反代/
  // 127.0.0.1，所以这里优先取 X-Forwarded-For 第一个值（反代会透传 XFF）来区分不同客户端；
  // 拿不到 XFF 时退化为 socket 地址（此时多个客户端共享一个计数桶，对自用场景可接受）。
  const loginFails = new Map(); // key -> { fails, lockUntil }
  const failKey = (req) => {
    const xff = String(req.headers['x-forwarded-for'] ?? '').split(',')[0]?.trim();
    return (xff && xff !== 'unknown') ? xff : (req.socket?.remoteAddress ?? '?');
  };
  const registerFail = (key, now) => {
    const cur = loginFails.get(key) ?? { fails: 0, lockUntil: 0 };
    const fails = cur.fails + 1;
    loginFails.set(key, { fails, lockUntil: fails > maxLoginAttempts ? now + loginLockMs : cur.lockUntil });
    return fails;
  };
  const failState = (key, now) => {
    const cur = loginFails.get(key);
    if (!cur) return { locked: false, fails: 0 };
    if (cur.lockUntil > now && cur.fails > maxLoginAttempts) return { locked: true, fails: cur.fails };
    if (cur.lockUntil <= now && cur.fails > maxLoginAttempts) { loginFails.set(key, { fails: 0, lockUntil: 0 }); return { locked: false, fails: 0 }; }
    return { locked: false, fails: cur.fails };
  };
  const server = createServer((req, res) => {
    // 访问日志钩子：每个请求 finish 时交由 onAccess（写网关自己的 access.log）记录。
    if (onAccess) {
      res.on('finish', () => { try { onAccess(req, res); } catch { /* 不能拖垮代理 */ } });
    }
    if (auth) {
      const token = auth.getToken?.() ?? null;
      const noPassword = !token;
      const authed = token ? authCheck(req, token) : false;

      // —— 尚未设置密码：强制先设置密码，其它任何请求都跳到设置页 ——
      if (noPassword) {
        if (req.method === 'POST' && req.url === '/gate/setup') {
          let body = '';
          req.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
          req.on('end', () => {
            const params = new URLSearchParams(body);
            const pw = String(params.get('password') ?? '').trim();
            const confirm = String(params.get('confirm') ?? '').trim();
            let err = null;
            if (!pw) err = '密码不能为空';
            else if (/^\d+$/.test(pw)) err = '密码不能是纯数字（至少含一个字母）';
            else if (!confirm) err = '请再次输入确认密码';
            else if (pw !== confirm) err = '两次输入的密码不一致';
            if (err || !onSetPassword) {
              res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
              res.end(setupPageHtml(err ?? '无法保存'));
              return;
            }
            onSetPassword(pw); // 持久化（写文件）
            res.writeHead(302, { location: '/', 'set-cookie': `${TOKEN_COOKIE}=${pw}; HttpOnly; SameSite=Lax; Path=/`, 'cache-control': 'no-store' });
            res.end();
          });
          return;
        }
        if (req.method === 'GET' && req.url === '/gate-setup') {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
          res.end(setupPageHtml(false));
          return;
        }
        // 其它任何请求 → 强制去设置页（此时不能访问 DSH）
        res.writeHead(302, { location: '/gate-setup' });
        res.end();
        return;
      }

      // 登录提交
      if (req.method === 'POST' && req.url === '/gate-login') {
        const key = failKey(req);
        const now = Date.now();
        const st = failState(key, now);
        if (st.locked) {
          const wait = Math.ceil(Math.max(st?.locked ? loginFails.get(key).lockUntil - now : 0, 0) / 1000);
          res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': String(wait) });
          res.end(loginPageHtml(`尝试次数过多，已临时锁定，请 ${wait}s 后重试`));
          return;
        }
        let body = '';
        req.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
        req.on('end', () => {
          const submitted = String(new URLSearchParams(body).get('token') ?? '');
          if (token && submitted === token) {
            loginFails.delete(key); // 成功登入清零
            res.writeHead(302, { location: '/', 'set-cookie': `${TOKEN_COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/`, 'cache-control': 'no-store' });
            res.end();
          } else {
            const fails = registerFail(key, now);
            if (fails > maxLoginAttempts) {
              res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': String(Math.ceil(loginLockMs / 1000)) });
              res.end(loginPageHtml('尝试次数过多，已临时锁定，请稍后重试'));
            } else {
              res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
              res.end(loginPageHtml(`密码错误（第 ${fails}/${maxLoginAttempts} 次）`));
            }
          }
        });
        return;
      }
      // 管理页
      if (req.method === 'GET' && req.url === '/gate/') {
        if (!authed) { res.writeHead(302, { location: '/gate-login' }); res.end(); return; }
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
        res.end(adminPageHtml(null, !!token));
        return;
      }
      // 修改密码 API
      if (req.method === 'POST' && req.url === '/gate/api/password') {
        if (!authed) { res.writeHead(401, { 'content-type': 'application/json' }); res.end('{"error":"unauthorized"}'); return; }
        let body = '';
        req.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
        req.on('end', () => {
          const pw = String(new URLSearchParams(body).get('password') ?? '').trim();
          if (pw && onSetPassword) onSetPassword(pw);
          res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.end('{"ok":true}');
        });
        return;
      }
      // 受保护：未认证 → 登录页 或 401
      if (token && !authed) {
        if (isHtmlRequest(req)) {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
          res.end(loginPageHtml(false));
        } else {
          res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.end('{"error":"unauthorized"}');
        }
        return;
      }
    }

    // /dsh-logs/ → 网关自带日志查看器(3082)。日志源是网关自己写的 access.log（含真实访客 IP，
    // 用于监控网关访问）。
    if (req.url && req.url.startsWith('/dsh-logs/')) {
      const headers = { ...req.headers };
      const proxyReq = httpRequest({ host: '127.0.0.1', port: 3082, method: req.method, path: req.url.replace('/dsh-logs/', '/'), headers, agent: false }, (proxyRes) => {
        res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
        proxyRes.pipe(res);
      });
      proxyReq.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('dsh-web-pass: logs upstream error'); });
      req.pipe(proxyReq);
      return;
    }

    const headers = loopbackAuthority({ ...req.headers }, upstream);
    const proxyReq = httpRequest({ host: upstream.host, port: upstream.port, method: req.method, path: req.url, headers, agent: false }, (proxyRes) => {
      const contentType = String(proxyRes.headers['content-type'] ?? '');
      const isCompressed = /gzip|br|deflate/i.test(String(proxyRes.headers['content-encoding'] ?? ''));
      // 只给未压缩的 HTML 文档注入 polyfill；压缩流注入会损坏页面
      if (injectHtml && contentType.includes('text/html') && !isCompressed) {
        const chunks = [];
        proxyRes.on('data', (c) => chunks.push(c));
        proxyRes.on('end', () => {
          let html = Buffer.concat(chunks).toString('utf8');
          if (!html.includes(INJECT_MARK)) html = html.replace(/<head[^>]*>/i, (m) => `${m}${injectHtml}`);
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
      // 响应原样透传（不再做任何再压缩），行为与 上游反向代理 proxy_pass 一致：
      // 压缩交给上级反向代理做（公网侧开启 gzip/br）。
      // 历史教训：这里自己做 brotli/gzip 再压缩会引入缓冲/背压问题导致大响应(长会话历史)卡死，
      // 所以干脆去掉，交给前端反代统一处理。
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
  });

  // WebSocket upgrade（DSH 的 /api/events.* 流式通道）原样透传
  server.on('upgrade', (req, socket, head) => {
    if (auth) {
      const token = auth.getToken?.() ?? null;
      if (token && !authCheck(req, token)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
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
      const actualPort = server.address().port;
      resolve({
        server,
        port: actualPort,
        close: () => new Promise((r) => { for (const s of clientSockets) { try { s.destroy(); } catch {} } server.close(() => r()); }),
      });
    });
  });
}
