// dsh-web-pass 核心：Host/Origin 改写反向代理 + 会话令牌认证 + 暗色主题
// 密码用 scrypt 哈希、cookie 存会话令牌（≠密码）、密码强度 ≥8 位+大小写+数字

import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';
import { connect as netConnect } from 'node:net';
import { randomBytes } from 'node:crypto';
import { loginPageHtml, setupPageHtml } from './gate-pages.mjs';
import { createGateRateLimiter } from './ratelimit.mjs';
import { passwordStrength } from './passwords.mjs';

const DEFAULT_UPSTREAM = { host: '127.0.0.1', port: 3080 };

const RANDOM_UUID_POLYFILL = `<script data-dsh-gate-polyfill="1">!function(){try{if(self.crypto&&!self.crypto.randomUUID){self.crypto.randomUUID=function(){var b=new Uint8Array(16);self.crypto.getRandomValues(b);b[6]=b[6]&15|64;b[8]=b[8]&63|128;var h="";for(var i=0;i<16;i++){var x=b[i].toString(16);h+=(x.length<2?"0":"")+x;if(i===3||i===5||i===7||i===9)h+="-";}return h;}}}catch(e){}}();</script>`;
export const DEFAULT_INJECT = RANDOM_UUID_POLYFILL;

// 退出浮标：注入非管理员条目的 HTML 页（访客/工具间没有设置页，需要 door 上的退出按钮）
const LOGOUT_CHIP_HTML = `<style id="dsh-gate-logout-style">#dsh-gate-logout{position:fixed;right:12px;bottom:12px;z-index:2147483647;font:12px/1.4 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:7px 12px;border-radius:999px;border:1px solid rgba(128,128,128,.45);background:rgba(127,127,127,.14);color:inherit;opacity:.55;transition:opacity .2s;text-decoration:none;backdrop-filter:blur(4px)}#dsh-gate-logout:hover{opacity:1}</style><a id="dsh-gate-logout" href="/gate/logout" title="退出密码门会话 | exit gate session" rel="noreferrer">🚪 退出</a>`;

export const SESSION_COOKIE = 'dws_session';
const SESSION_MAX_AGE = 172800; // 2 天（与服务端 SESSION_TTL_MS 对齐；滑动续期时重下）
// 首设一次性令牌 cookie（v0.3.5）：防 /gate/setup 无鉴权窗口内的跨站抢注表单
const SETUP_COOKIE = 'dws_setup';
// 注入/改写需要全量缓冲响应体；为防超大响应把与 DSH 同进程的门拖 OOM（v0.3.4 审计），
// 缓冲设 8MB 上限，超限自动降级为流式透传（放弃注入/改写）
const INJECT_MAX_BYTES = 8 * 1024 * 1024;
// 上游空闲超时：无数据 2 分钟即掐断（慢上游不再无限占用连接）
const UPSTREAM_IDLE_MS = 120_000;

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
function isHttps(req, trustProxy = false) {
  if (req.socket?.encrypted === true) return true;
  // v0.3.5：X-Forwarded-Proto 仅在显式信任反代时采纳（与 trustProxy 语义一致；
  // 此前无条件采信，直连客户端可自诱导 Secure cookie）
  if (!trustProxy) return false;
  return String(req.headers['x-forwarded-proto'] ?? '').toLowerCase() === 'https';
}
function securityHeaders() {
  return {
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'x-robots-tag': 'noindex, nofollow',
  };
}
function sessionCookie(token, maxAge, req, trustProxy = false) {
  let c = `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
  if (isHttps(req, trustProxy)) c += '; Secure';
  return c;
}
function clearSessionCookie(req, trustProxy = false) {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0` + (isHttps(req, trustProxy) ? '; Secure' : '');
}

// 滑动续期：服务端刚续了有效期就顺手重下浏览器 cookie（否则浏览器侧先过期）。
// 只追加不覆盖上游自带的 Set-Cookie。调用点都在发响应头之前，故直接 appendHeader
// 即可，无需再包装 writeHead。（v0.3.5 提升到模块级，供 proxyForward 使用）
function attachSessionRefresh(res, req, token, trustProxy = false) {
  try { res.appendHeader('set-cookie', sessionCookie(token, SESSION_MAX_AGE, req, trustProxy)); } catch {}
}

export function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

// ---- 密码强度校验 ----
// v0.3.5：唯一实现在 lib/passwords.mjs（本文件 setup 端点与 index.js RPC 共用同一份）。

function isHtmlRequest(req) {
  const accept = String(req.headers.accept ?? '');
  return accept.includes('text/html') || req.url === '/' || /\.html?$/i.test(String(req.url));
}

function loopbackAuthority(headers, upstream) {
  const authority = `${upstream.host}:${upstream.port}`;
  headers.Host = authority;
  if (headers.origin) headers.origin = `http://${authority}`;
  if (headers.Origin) headers.Origin = `http://${authority}`;
  // v0.3.5：统一剥离门自身会话 cookie——无论条目类型。
  // dsh:true 条目稍后由代持 cookie 整体覆盖；dsh:false 条目（fnOS/openclaw 等）
  // 绝不应收到门的会话令牌（上游日志/反射面可读取并回放）。
  if (headers.cookie !== undefined) {
    const kept = String(headers.cookie).split(';').map((p) => p.trim()).filter((p) => p && !p.startsWith(SESSION_COOKIE + '='));
    if (kept.length) headers.cookie = kept.join('; ');
    else delete headers.cookie;
  }
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
  // 首设一次性令牌（仅 hasPassword=false 窗口使用）：{ token, at }
  let pendingSetup = null;
  // 登录防爆破限速器（v0.3.5 抽离到 lib/ratelimit.mjs）：
  // per-IP 计数、成功登录不清零、真锁定+指数退避（语义见 ratelimit.mjs 文件头）
  const rl = createGateRateLimiter({ trustProxy, maxLoginAttempts, loginLockMs });

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
      // v0.3.5：滑动续期的 cookie 重下移到「即将转发上游」处（见 proxyForward refreshToken）。
      // 门自身端点（login/setup/logout）不再被追加续期 Set-Cookie——
      // 此前会把重登 302 变成 [新token, 旧token]（浏览器保留旧 token，新 token 成孤儿），
      // 甚至把 logout 的 Max-Age=0 覆盖成续期（登出失效）。

      // ---- 尚未设置密码：强制先设置 ----
      if (!hasPassword) {
        if (req.method === 'POST' && req.url === '/gate/setup') {
          // v0.3.5 一次性令牌：GET /gate-setup 下发 HttpOnly cookie，POST 必须携带同值——
          // 封堵无鉴权窗口内「跨站自动提交表单抢注密码门」的路径（SameSite 拦不住请求本身）。
          const setupTok = parseCookies(req.headers.cookie)[SETUP_COOKIE];
          if (!pendingSetup || Date.now() - pendingSetup.at > 15 * 60_000 || setupTok !== pendingSetup.token) {
            pendingSetup = null;
            res.writeHead(403, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
            res.end(setupPageHtml('设置页已过期，请重新打开 /gate-setup | setup page expired, please reopen /gate-setup'));
            return;
          }
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
              pendingSetup = null; // 首设完成，一次性令牌即刻作废
              const tok = auth.createSession(0);
              res.writeHead(302, {
                location: '/',
                'set-cookie': [sessionCookie(tok, SESSION_MAX_AGE, req, trustProxy), `${SETUP_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`],
                'cache-control': 'no-store',
              });
              res.end();
            } catch (e) {
              res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
              res.end(setupPageHtml('保存失败：' + (e.message || String(e))));
            }
          });
          return;
        }
        if (req.method === 'GET' && req.url === '/gate-setup') {
          const tok = randomBytes(16).toString('hex');
          pendingSetup = { token: tok, at: Date.now() };
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'set-cookie': `${SETUP_COOKIE}=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900` + (isHttps(req, trustProxy) ? '; Secure' : '') });
          res.end(setupPageHtml(false));
          return;
        }
        {
          // 302 → /gate-setup：顺带下发一次性令牌（随后 GET 会再刷新一次，无害）
          const tok = randomBytes(16).toString('hex');
          pendingSetup = { token: tok, at: Date.now() };
          res.writeHead(302, { location: '/gate-setup', 'set-cookie': `${SETUP_COOKIE}=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900` + (isHttps(req, trustProxy) ? '; Secure' : '') });
          res.end(); return;
        }
      }

      // ---- 登录（单密码框按顺序试各条目；报错保持笼统，不透露哪条）----
      if (req.method === 'POST' && req.url === '/gate-login') {
        const ip = rl.failKey(req);
        const remainMs = rl.lockRemainingMs(ip);
        if (remainMs > 0) {
          const secs = Math.max(1, Math.ceil(remainMs / 1000));
          res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': String(secs) });
          res.end(loginPageHtml(`尝试次数过多，请 ${secs} 秒后重试`));
          return;
        }
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
              rl.recordFailure(ip);
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
            // v0.3.5：成功登录不再清零失败计数（防「任一条目成功→清零→无限爆破其它条目」）；
            // 并轮换会话：同浏览器旧 token 即刻作废（不再产生孤儿会话）。
            const tok = auth.createSession(idx);
            if (sessionToken && sessionToken !== tok) { try { auth.destroySession(sessionToken); } catch {} }
            res.writeHead(302, { location: '/', 'set-cookie': sessionCookie(tok, SESSION_MAX_AGE, req, trustProxy), 'cache-control': 'no-store' });
            res.end();
          }).catch((e) => {
            // auth.verify 抛异常（如 scrypt 解析错误）：记录错误，显示友好提示，不崩溃进程
            rl.recordFailure(ip);
            try { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); } catch {}
            try { res.end(loginPageHtml('密码验证异常，请重试')); } catch {}
          });
        });
        return;
      }

      // ---- 登出（POST/GET 皆可：设置页按钮用 POST，浮标/手动地址用 GET）----
      if ((req.method === 'POST' || req.method === 'GET') && req.url === '/gate/logout') {
        if (sessionToken) auth.destroySession(sessionToken);
        res.writeHead(302, { location: '/gate-login', 'set-cookie': clearSessionCookie(req, trustProxy), 'cache-control': 'no-store' });
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
        if (sess?.renewed && sessionToken) attachSessionRefresh(res, req, sessionToken, trustProxy);
        const logHeaders = { ...req.headers };
        const logReq = httpRequest({ host: '127.0.0.1', port: 3082, method: req.method, path: req.url.replace('/dsh-logs/', '/'), headers: logHeaders, agent: false, timeout: 30_000 }, (logRes) => {
          res.writeHead(logRes.statusCode ?? 502, logRes.headers);
          logRes.pipe(res);
        });
        logReq.on('timeout', () => { try { logReq.destroy(); } catch {} });
        logReq.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('dsh-web-pass: logs upstream error'); });
        req.pipe(logReq);
        return;
      }

      // ---- 已认证：代理到会话条目对应的上游（非管理员条目注入退出浮标）----
      const up = routeOf(sess?.entry ?? 0);
      await proxyForward(req, res, { upstream: up, injectHtml, dshAuth: dshAuthOf(sess?.entry ?? 0), clientHostTrust: up.clientHostTrust !== false, logoutChip: (sess?.entry ?? 0) !== 0, refreshToken: sess?.renewed ? sessionToken : null, trustProxy });
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
  server.maxConnections = 512; // 并发连接上限（v0.3.5：防慢连接堆积拖垮同进程的 dsh web）
  server.on('connection', (sock) => { clientSockets.add(sock); sock.on('close', () => clientSockets.delete(sock)); sock.on('error', () => {}); });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      resolve({ server, port: server.address().port, close: () => new Promise((r) => { for (const s of clientSockets) { try { s.destroy(); } catch {} } server.close(() => r()); }) });
    });
  });
}

// 注入/改写前全量缓冲响应体（带上限）：超限自动降级为流式透传并放弃注入/改写——
// 防止超大 text/html 把与 DSH 同进程的门（整个 dsh web）拖 OOM（v0.3.4 审计确认）。
// 同时统一处理客户端中途断开：立即掐断上游，不再对已销毁的 res 写入。
function collectBody(proxyRes, res, onDone) {
  const chunks = [];
  let total = 0;
  let overflow = false;
  const abort = () => { try { proxyRes.destroy(); } catch {} try { res.destroy(); } catch {} };
  res.on('error', () => abort());
  res.on('close', () => { if (!res.writableEnded) abort(); });
  proxyRes.on('data', (c) => {
    if (overflow) return;
    total += c.length;
    chunks.push(c);
    if (total > INJECT_MAX_BYTES) {
      overflow = true;
      try {
        const h = { ...proxyRes.headers };
        delete h['content-length']; delete h['transfer-encoding'];
        h['cache-control'] = 'no-cache';
        res.writeHead(proxyRes.statusCode ?? 200, h);
        for (const c2 of chunks) res.write(c2);
        chunks.length = 0;
        proxyRes.pipe(res);
        console.warn('dsh-web-pass: 响应超出注入缓冲上限(8MB)，已降级为流式透传（跳过注入/改写）');
      } catch { abort(); }
    }
  });
  proxyRes.on('end', () => {
    if (overflow) return; // 降级路径由 pipe 自动收尾
    try { onDone(Buffer.concat(chunks)); } catch { abort(); }
  });
  proxyRes.on('error', () => res.destroy());
}

// 改写类响应统一出口：collectBody（8MB 上限 + 断连中止）→ 文本改写 → 发回。
// body 已改写：验证器与缓存头一并作废（防门前反代把「改写后」实体按原验证器固化）。
function sendRewritten(proxyRes, res, rewrite) {
  collectBody(proxyRes, res, (buf) => {
    const out = Buffer.from(rewrite(buf.toString('utf8')), 'utf8');
    const h = { ...proxyRes.headers };
    delete h['content-length']; delete h['transfer-encoding'];
    delete h.etag; delete h['last-modified'];
    h['content-length'] = String(out.length);
    h['cache-control'] = 'no-cache';
    res.writeHead(proxyRes.statusCode ?? 200, h);
    res.end(out);
  });
}

async function proxyForward(req, res, { upstream, injectHtml, dshAuth, clientHostTrust = true, logoutChip = false, refreshToken = null, trustProxy = false } = {}) {
  const up = upstream ?? DEFAULT_UPSTREAM;
  // 安全头（x-frame-options: DENY 等）只应属于门自身页面（登录页/日志页）。
  // handler 顶部给所有响应统一 setHeader 了这四个头；代理转发时必须移除，
  // 还原为上游的原始响应头——否则 fnOS 等后端用同源 iframe 嵌套件应用的页面
  // 会被 DENY 整页挡成「拒绝连接」（Docker/套件经门全空白即此因）。
  // writeHead 时上游自带的安全头（如有）会原样生效，不受此移除影响。
  for (const k of ['x-content-type-options', 'x-frame-options', 'referrer-policy', 'x-robots-tag']) res.removeHeader(k);
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
  // 滑动续期：服务端刚续了有效期就顺手重下浏览器 cookie（v0.3.5 起仅在转发路径执行，
  // 门自身端点的 302 不再被追加续期 Set-Cookie）
  if (refreshToken) attachSessionRefresh(res, req, refreshToken, trustProxy);
  let proxyReq;
  const destroyUp = () => { try { proxyReq?.destroy(); } catch {} };
  let reqDone = false;
  req.on('end', () => { reqDone = true; });
  req.on('close', () => { if (!reqDone) destroyUp(); }); // 请求侧中止：客户端上传中断即掐断上游
  res.on('close', () => { if (!res.writableEnded) destroyUp(); });
  proxyReq = httpRequest({ host: up.host, port: up.port, method: req.method, path: req.url, headers, agent: false, timeout: UPSTREAM_IDLE_MS }, (proxyRes) => {
    const contentType = String(proxyRes.headers['content-type'] ?? '');
    const isCompressed = /gzip|br|deflate/i.test(String(proxyRes.headers['content-encoding'] ?? ''));
    // 注入 UUID polyfill（非安全上下文 HTTP 需要）+ 退出浮标（非管理员条目）
    if ((injectHtml || logoutChip) && contentType.includes('text/html') && !isCompressed) {
      sendRewritten(proxyRes, res, (html) => {
        if (injectHtml && !html.includes('data-dsh-gate-polyfill')) html = html.replace(/<head[^>]*>/i, (m) => `${m}${DEFAULT_INJECT}`);
        // 浮标优先插在 <body> 开头（fixed 定位不受插入点影响）；无 body 标签则放弃（非标准页）
        if (logoutChip && !html.includes('dsh-gate-logout') && /<body[^>]*>/i.test(html)) html = html.replace(/<body[^>]*>/i, (m) => `${m}${LOGOUT_CHIP_HTML}`);
        return html;
      });
      return;
    }
    // 定向改写 client-connection 模块（见文件头「非 loopback 页面解锁 Host 设置」注释）
    if (clientHostTrust && !isCompressed
      && contentType.includes('javascript')
      && String(req.url ?? '').includes(REWRITE_MODULE_MARK)) {
      sendRewritten(proxyRes, res, (js) => {
        if (js.includes(REWRITE_ANCHOR)) {
          js = js.replace(REWRITE_ANCHOR, `(${REWRITE_ANCHOR} || !0)`);
          console.info('dsh-web-pass: 已改写 client-connection 模块（非 loopback 页面启用 host 设置模式）');
        } else {
          console.warn('dsh-web-pass: 未找到 isLoopback 锚点，模块原样透传（DSH 版本可能已更新，请同步更新 REWRITE_ANCHOR）');
        }
        return js;
      });
      return;
    }
    // 响应原样透传（压缩交给前端反向代理做）
    res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
    proxyRes.pipe(res);
    res.on('close', () => proxyRes.destroy());
    proxyRes.on('error', () => res.destroy());
  });
  proxyReq.on('timeout', () => { try { proxyReq.destroy(new Error('upstream idle timeout')); } catch {} });
  proxyReq.on('error', (err) => {
    // v0.3.5：对外统一文案，不再泄漏内部 host:port 与 Node 错误细节（细节进服务端日志）
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    try { res.end('dsh-web-pass: 上游暂不可达 | upstream unreachable'); } catch {}
    console.warn(`dsh-web-pass: 上游 ${up.host}:${up.port} 连接失败 | ${err?.message ?? err}`);
  });
  req.pipe(proxyReq);
}
