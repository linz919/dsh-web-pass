// dsh-web-pass 访问日志：网关自带记录访客 IP（HMAC 假名化） + 内嵌日志查看器（127.0.0.1:3082）。
// 日志里不落原始 IP——用 HMAC-SHA256(key, ip) 产生固定假名，便于聚合分析同时不泄隐私。
import { createServer } from 'node:http';
import { appendFile, readFile, mkdir, stat, rename, readdir, unlink } from 'node:fs/promises';
import { dirname, basename, join } from 'node:path';
import { createHmac, randomBytes } from 'node:crypto';

/** 默认单文件上限 1MB、最多保留 7 份历史 → 日志总体积有硬上限（约 8MB）。 */
export const DEFAULT_LOG_MAX_BYTES = 1024 * 1024;
export const DEFAULT_LOG_MAX_FILES = 7;

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const LINE_RE = /^(?<ip>\S+) - - \[(?<time>[^\]]+)\] "(?<request>[^"]*)" (?<status>\d{3}) (?<bytes>\S+) "(?<referer>[^"]*)" "(?<ua>[^"]*)"$/;

// ---- HMAC IP 假名化（不落原始 IP）----
let hmacKey = null;
// 进程内临时密钥：磁盘密钥尚未加载完成时使用（随机、每次启动不同），
// 绝不用公开常量回退——否则该窗口内所有 IP 的假名可被任何人离线重算。
const EPHEMERAL_HMAC_KEY = randomBytes(32).toString('hex');
function getHmacKey() {
  // 磁盘密钥由 createAccessLogger 首次运行时异步加载/生成
  return hmacKey ?? EPHEMERAL_HMAC_KEY;
}
function setHmacKey(key) { hmacKey = key; }

function anonymizeIp(ip) {
  if (!ip || typeof ip !== 'string') return '-';
  // 聚合前缀先行：IPv4 取 /24、IPv6 取 /64（IPv4-mapped IPv6 先还原成 IPv4 再算）
  let v = String(ip);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(v);
  if (mapped) v = mapped[1];
  const prefix = v.includes('.')
    ? `${v.split('.').slice(0, 3).join('.')}.0/24`
    : `${v.split(':').slice(0, 4).join(':')}::/64`;
  // 假名 = HMAC-SHA256(key, 原始IP) 截 12 个十六进制位；key 只在网关侧，假名不可逆
  let mac = 'err';
  try { mac = createHmac('sha256', getHmacKey()).update(ip).digest('hex').slice(0, 12); } catch { /* 忽略 */ }
  return `${prefix}#${mac}`;
}

function pad(n) { return String(n).padStart(2, '0'); }
/** nginx 风格时间：20/Aug/2026:15:00:00 +0000 */
function nginxTime(d) {
  return `${pad(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}
/** 把日志里的 nginx 时间（21/Aug/2026:12:38:25 +0000）解析成 Date；格式不符返回 null。 */
function parseNginxTime(s) {
  const m = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(String(s));
  if (!m) return null;
  const mon = MONTHS.indexOf(m[2]);
  if (mon < 0) return null;
  const utc = Date.UTC(+m[3], mon, +m[1], +m[4], +m[5], +m[6]);
  const offMin = (+m[8]) * 60 + (+m[9]);
  return new Date(utc + (m[7] === '-' ? offMin : -offMin) * 60000);
}
/** 渲染成服务器本地时区的 YYYY-MM-DD HH:mm:ss（查看器展示用；文件里始终存 UTC）。 */
function localTimeStr(d) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
/**
 * 真实访客 IP：CF-Connecting-IP（Cloudflare）> X-Forwarded-For 第一个 > socket 地址。
 * @param {import('node:http').IncomingMessage} req
 * @param {boolean} trustProxy 仅当网关前面有可信反向代理时才信任转发头；
 *   默认 false——防止伪造 XFF 头污染日志（与登录限速的取值逻辑保持一致）。
 */
export function peerIp(req, trustProxy = false) {
  const socketIp = req.socket?.remoteAddress ?? '-';
  if (!trustProxy) return socketIp;
  const cf = String(req.headers['cf-connecting-ip'] ?? '').trim();
  if (cf && cf !== 'unknown') return cf.split(',')[0].trim();
  const xff = String(req.headers['x-forwarded-for'] ?? '').split(',')[0]?.trim();
  return (xff && xff !== 'unknown') ? xff : socketIp;
}

/** 构造 nginx-combined 风格的一行访问日志（IP 已假名化）。 */
export function buildAccessLine(req, res, trustProxy = false) {
  const ip = anonymizeIp(peerIp(req, trustProxy));
  const time = nginxTime(new Date());
  const method = String(req.method ?? '');
  const url = String(req.url ?? '/');
  const request = `${method} ${url} HTTP/1.1`;
  const status = res.statusCode ?? 0;
  const len = res.getHeader('content-length');
  const bytes = (len !== undefined && len !== null) ? String(len) : '-';
  const referer = String(req.headers.referer ?? '-');
  const ua = String(req.headers['user-agent'] ?? '-');
  return `${ip} - - [${time}] "${request}" ${status} ${bytes} "${referer}" "${ua}"`;
}

/**
 * 访问日志写入器。运行常驻，每次请求 finish 时 append 一行；**按大小轮转、最多保留 maxFiles 份历史**：
 * 写入前发现 access.log 已达到 maxBytes，就把它滚动为 access.log.1（更早的依次后移为
 * access.log.2 … access.log.N），超出 maxFiles 的最旧文件直接删除——
 * 单文件与总体积都有硬上限，不随时间无限增大。
 * @param {{ file: string, maxBytes?: number, maxFiles?: number, trustProxy?: boolean }} opts
 */
export function createAccessLogger({ file, maxBytes = DEFAULT_LOG_MAX_BYTES, maxFiles = DEFAULT_LOG_MAX_FILES, trustProxy = false }) {
  const dir = dirname(file);
  const base = basename(file);
  const capBytes = Math.max(64 * 1024, Number(maxBytes) || DEFAULT_LOG_MAX_BYTES); // 下限 64KB，防止误配 0/负数
  const keepFiles = Math.max(1, Math.min(100, Math.floor(Number(maxFiles) || DEFAULT_LOG_MAX_FILES)));

  // HMAC 密钥：首次生成并存盘，之后复用（保证同一 IP 的假名可聚合）
  const hmacKeyPath = join(dir, '.hmac-key');
  (async () => {
    try {
      const existing = (await readFile(hmacKeyPath, 'utf8')).trim();
      if (existing.length >= 32) { setHmacKey(existing); return; }
    } catch {}
    try { await mkdir(dir, { recursive: true }); } catch {}
    const key = randomBytes(32).toString('hex');
    await appendFile(hmacKeyPath, key + '\n', { mode: 0o600 }).catch(() => {});
    setHmacKey(key);
  })().catch(() => { setHmacKey(EPHEMERAL_HMAC_KEY); });

  let ok = false;
  const ensure = async () => { if (ok) return; try { await mkdir(dir, { recursive: true }); ok = true; } catch { /* 忽略 */ } };
  let rotating = false;
  const rotate = async () => {
    if (rotating) return; rotating = true;
    try {
      let size;
      try { size = (await stat(file)).size; } catch { return; } // 文件还不存在
      if (size < capBytes) return; // 未达上限，无需轮转
      // 依次后移：access.log.(N-1) → access.log.N … access.log → access.log.1
      for (let i = keepFiles - 1; i >= 1; i--) {
        await rename(join(dir, `${base}.${i}`), join(dir, `${base}.${i + 1}`)).catch(() => {});
      }
      await rename(file, join(dir, `${base}.1`)).catch(() => {});
      // 清理超出保留份数的编号历史文件；旧版按天轮转遗留的 .YYYY-MM-DD 文件不动，需手动删除
      try {
        const prefix = base + '.';
        for (const e of await readdir(dir)) {
          if (!e.startsWith(prefix)) continue;
          const n = e.slice(prefix.length);
          if (!/^\d+$/.test(n)) continue;
          if (Number(n) > keepFiles) await unlink(join(dir, e)).catch(() => {});
        }
      } catch { /* 忽略 */ }
    } finally { rotating = false; }
  };
  void ensure();
  /** @param {import('node:http').IncomingMessage} req @param {import('node:http').ServerResponse} res */
  return {
    async log(req, res) {
      const line = buildAccessLine(req, res, trustProxy);
      try { await rotate(); await appendFile(file, line + '\n', 'utf8'); }
      catch { /* 磁盘/权限问题静默，不能让代理因此挂掉 */ }
    },
  };
}

/**
 * 内嵌日志查看器：127.0.0.1:3082，读取 access.log 渲染成表格（可按 IP 筛选）。
 * 只服务 GET，样式内联，稳在子路径代理下也能用。
 */
export function createLogViewer({ file, host = '127.0.0.1', port = 3082, limit = 1000 }) {
  const server = createServer(async (req, res) => {
    try {
      if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405).end(); return; }
      const u = new URL(req.url ?? '/', 'http://x');
      if (u.pathname !== '/' && u.pathname !== '/index.html') { res.writeHead(404); res.end('not found'); return; }
      const filter = String(u.searchParams.get('ip') ?? '').toLowerCase();
      const want = Math.min(5000, Math.max(1, Number(u.searchParams.get('limit')) || limit));
      let lines = [];
      try {
        const raw = await readFile(file, 'utf8');
        const all = raw.split('\n').filter(Boolean);
        lines = all.slice(-want);
      } catch { /* 文件还没生成 */ }

      const rows = [];
      for (let l = lines.length - 1; l >= 0; l--) { // 最新在上
        const line = lines[l];
        const m = LINE_RE.exec(line);
        if (!m) continue;
        const g = m.groups;
        if (filter && !(`${g.ip} ${g.request}`.toLowerCase().includes(filter))) continue;
        const st = statusLabel(g.status);
        const t = parseNginxTime(g.time); // 文件存 UTC，展示转服务器本地时区
        const timeShow = t ? localTimeStr(t) : g.time;
        rows.push(
          `<tr><td>${esc(g.ip)}</td><td>${esc(timeShow)}</td><td class="req">${esc(g.request)}</td>` +
          `<td class="${st.cls}">${st.txt}${st.code ? ` <span style="opacity:.5">${st.code}</span>` : ''}</td>` +
          `<td>${esc(g.bytes)}</td><td class="small">${esc(g.referer)}</td><td class="small">${esc(g.ua)}</td></tr>`
        );
      }
      const body = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5"><title>dsh-web-pass 访问日志</title>
<style>
body{margin:0;background:#11181f;color:#e6edf3;font:14px/1.5 -apple-system,"PingFang SC","Microsoft YaHei",monospace}
header{padding:18px 24px;background:#1c2733;border-bottom:1px solid #2d3b49}
h1{margin:0 0 12px;font-size:20px}
form{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input,button{font:inherit;padding:7px 12px;border-radius:6px;border:1px solid #3b4a5a;background:#22303e;color:#fff}
button{background:#e17055;border-color:#b33939;cursor:pointer}
.count{color:#9fb3c8;margin:8px 0 0}
main{padding:18px 24px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border-bottom:1px solid #26333f;padding:8px 10px;text-align:left;white-space:nowrap}
th{background:#1c2733;position:sticky;top:0}
td.req{max-width:420px;overflow:hidden;text-overflow:ellipsis}
td.small{max-width:260px;overflow:hidden;text-overflow:ellipsis;color:#9fb3c8}
td.ok{color:#3fb950;font-weight:600}
td.bad{color:#f85149;font-weight:600}
</style></head><body><header>
<h1>🛰 dsh-web-pass 访问日志（网关 3081）｜密码验证记录</h1>
<p class="count">显示 ${rows.length} 条 · 时间为服务器本地时区（文件存 UTC）· 每 5 秒自动刷新 · <a href="/" style="color:#9fb3c8">立即刷新</a></p>
<form method="get" action="/"><input name="ip" placeholder="按 IP / 请求筛选" value="${esc(u.searchParams.get('ip') ?? '')}">
<input name="limit" type="number" min="1" max="5000" value="${want}" style="width:110px"><button type="submit">筛选</button></form>
</header><main><table><thead><tr><th>IP</th><th>时间</th><th>请求</th><th>验证结果</th><th>大小</th><th>来源</th><th>UA</th></tr></thead>
<tbody>${rows.join('') || '<tr><td colspan="7" style="color:#9fb3c8">暂无记录 | no records yet</td></tr>'}</tbody></table></main></body></html>`;
      const buf = Buffer.from(body, 'utf8');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': String(buf.length), 'cache-control': 'no-store' });
      if (req.method !== 'HEAD') res.end(buf); else res.end();
    } catch {
      try { res.writeHead(500).end('internal error'); } catch { /* 忽略 */ }
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const actual = server.address().port;
      resolve({ server, port: actual, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

/** 把网关密码验证的状态码翻译成人话：302=成功，200=密码错误，401=超次锁定。code 为原始码（淡化显示）。 */
function statusLabel(s) {
  if (s === '302') return { txt: '✅ 验证成功', cls: 'ok', code: '302' };
  if (s === '401') return { txt: '❌ 验证失败·已锁定', cls: 'bad', code: '401' };
  if (s === '200') return { txt: '❌ 验证失败', cls: 'bad', code: '200' };
  return { txt: String(s ?? ''), cls: '' };
}
