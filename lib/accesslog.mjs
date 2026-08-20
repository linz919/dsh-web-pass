// dsh-web-pass 访问日志：网关自带记录访客 IP + 内嵌日志查看器（127.0.0.1:3082）。
// 为什么要自己做：3081 域名的流量走「反向代理 → 网关 3081 → 3080」，
// 不经过 上游的反向代理，所以 前端反代的日志记不到。
// 由网关自己把每个请求写进 $DSH_HOME/dsh-gate/access.log，再起一个查看器在 3082。
import { createServer } from 'node:http';
import { appendFile, readFile, mkdir, stat, rename, readdir, unlink } from 'node:fs/promises';
import { dirname, basename, join } from 'node:path';

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const LINE_RE = /^(?<ip>\S+) - - \[(?<time>[^\]]+)\] "(?<request>[^"]*)" (?<status>\d{3}) (?<bytes>\S+) "(?<referer>[^"]*)" "(?<ua>[^"]*)"$/;

function pad(n) { return String(n).padStart(2, '0'); }
/** nginx 风格时间：20/Aug/2026:15:00:00 +0000 */
function nginxTime(d) {
  return `${pad(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}
/** 真实访客 IP：CF-Connecting-IP（Cloudflare）> X-Forwarded-For 第一个 > socket 地址。 */
export function peerIp(req) {
  const cf = String(req.headers['cf-connecting-ip'] ?? '').trim();
  if (cf && cf !== 'unknown') return cf.split(',')[0].trim();
  const xff = String(req.headers['x-forwarded-for'] ?? '').split(',')[0]?.trim();
  return (xff && xff !== 'unknown') ? xff : (req.socket?.remoteAddress ?? '-');
}

/** 构造 nginx-combined 风格的一行访问日志。 */
export function buildAccessLine(req, res, startMs) {
  const ip = peerIp(req);
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
 * 访问日志写入器。运行常驻，每次请求 finish 时 append 一行；**按天轮转、保留 keepDays 天**：
 * 发现 access.log 的最后写入日期不是今天，就把旧文件改成 access.log.YYYY-MM-DD，并删除早于
 * keepDays 天的轮转文件——体积有界，不会无限增大。
 * @param {{ file: string, keepDays?: number }} opts
 */
export function createAccessLogger({ file, keepDays = 30 }) {
  let ok = false;
  const ensure = async () => { if (ok) return; try { await mkdir(dirname(file), { recursive: true }); ok = true; } catch { /* 忽略 */ } };
  let rotating = false;
  const rotate = async () => {
    if (rotating) return; rotating = true;
    try {
      let mtimeMs;
      try { const st = await stat(file); if (!st.size) return; mtimeMs = st.mtimeMs; } catch { return; }
      const logDay = dayStr(new Date(mtimeMs));
      if (logDay === dayStr(new Date())) return; // 仍是今天
      await rename(file, `${file}.${logDay}`).catch(() => {});
      try {
        const prefix = basename(file) + '.';
        for (const e of await readdir(dirname(file))) {
          if (!e.startsWith(prefix)) continue;
          const d = e.slice(prefix.length);
          if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) continue;
          if ((Date.now() - Date.parse(d)) > keepDays * 86400000) await unlink(join(dirname(file), e)).catch(() => {});
        }
      } catch { /* 忽略 */ }
    } finally { rotating = false; }
  };
  void ensure();
  /** @param {import('node:http').IncomingMessage} req @param {import('node:http').ServerResponse} res */
  return {
    async log(req, res) {
      const line = buildAccessLine(req, res);
      try { await rotate(); await appendFile(file, line + '\n', 'utf8'); }
      catch { /* 磁盘/权限问题静默，不能让代理因此挂掉 */ }
    },
  };
}

function dayStr(d) { const p = (n) => String(n).padStart(2, '0'); return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`; }

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
        rows.push(
          `<tr><td>${esc(g.ip)}</td><td>${esc(g.time)}</td><td class="req">${esc(g.request)}</td>` +
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
<p class="count">显示 ${rows.length} 条 · 每 5 秒自动刷新 · <a href="/" style="color:#9fb3c8">立即刷新</a></p>
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
