// dsh-web-pass 插件入口：安全加固版
// 密码用 scrypt 哈希、会话用随机令牌（cookie ≠ 密码）、密码强度 ≥8 位+大小写+数字
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, renameSync } from 'node:fs';
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { join, dirname } from 'node:path';
import { homedir, networkInterfaces } from 'node:os';
import { promisify } from 'node:util';
import { createGateProxy, DEFAULT_INJECT, probeTcp, SESSION_COOKIE, parseCookies } from './proxy.mjs';
import { createAccessLogger, createLogViewer } from './accesslog.mjs';
import { DshAuthProvider } from './dsh-auth.mjs';

// ---- RPC 契约 ----
export const GATE_RPC_CHANNEL = '/dsh-web-pass';
export const GATE_ENDPOINTS = Object.freeze({
  status: 'webpass.status',
  passwordSet: 'webpass.password.set',
  entrySet: 'webpass.entry.set',
  entryDel: 'webpass.entry.del',
  entryAdd: 'webpass.entry.add',
});

function rpcOk(value) { return { ok: true, value }; }
function rpcFail(message) { return { ok: false, error: { code: 'bad-request', message, details: { issues: [{ message }] } } }; }

function installGateRpc(ctx, { auth, getStatus, addEntry = null, onEntryDeleted = null, log = console } = {}) {
  if (!ctx?.connection?.rpc?.handle) {
    log.warn?.('dsh-web-pass: Connection RPC unavailable — 设置页不可用');
    return () => {};
  }
  return ctx.connection.rpc.handle(GATE_RPC_CHANNEL, async (endpoint, payload = {}) => {
    try {
      if (endpoint === GATE_ENDPOINTS.status) return rpcOk(await getStatus());
      if (endpoint === GATE_ENDPOINTS.passwordSet) {
        // 统一密码重设框：{entry, password, confirm}，不验原密码（登录态即凭证）。
        // 兼容旧客户端：缺 entry 视为 0；附带的 current 直接忽略。
        const idx = Number.isInteger(payload?.entry) ? payload.entry : 0;
        if (!auth.isVisible(idx)) return rpcFail('未知条目 | unknown entry');
        const pw = String(payload?.password ?? '').trim();
        const confirm = String(payload?.confirm ?? '').trim();
        if (!pw) return rpcFail('密码不能为空 | password required');
        const st = passwordStrength(pw);
        if (!st.ok) return rpcFail(st.reason);
        if (!confirm) return rpcFail('请再次输入确认密码 | confirmation required');
        if (pw !== confirm) return rpcFail('两次输入的密码不一致 | passwords do not match');
        const clash = await auth.clashes(idx, pw);
        if (clash) return rpcFail('与其它入口密码相同，请换一个 | same as another entry');
        await auth.setPasswordHash(idx, pw);
        auth.destroyEntrySessions(idx);
        return rpcOk({ ok: true });
      }
      if (endpoint === GATE_ENDPOINTS.entrySet) {
        // 开关条目（即时生效，无需重起）：{entry, enabled}；管理员条目（0）恒开。
        const idx = Number(payload?.entry);
        if (!Number.isInteger(idx) || idx <= 0 || !auth.isKnown(idx)) return rpcFail('未知条目 | unknown entry');
        const enabled = payload?.enabled !== false;
        auth.setEnabled(idx, enabled);
        if (!enabled) auth.destroyEntrySessions(idx);
        return rpcOk({ ok: true });
      }
      if (endpoint === GATE_ENDPOINTS.entryDel) {
        // 删除条目（即时生效，patch 里删行后重起则彻底消失）：{entry}；管理员条目不可删。
        // 软删保序：行标记隐藏、会话吊销，其余条目序号不动（会话按序号绑定）。
        const idx = Number(payload?.entry);
        if (!Number.isInteger(idx) || idx <= 0 || !auth.isKnown(idx)) return rpcFail('未知条目 | unknown entry');
        auth.setDeleted(idx, true);
        auth.destroyEntrySessions(idx);
        try { onEntryDeleted?.(idx); } catch {}
        return rpcOk({ ok: true });
      }
      if (endpoint === GATE_ENDPOINTS.entryAdd) {
        // 设置页表单新增：{label, host, port, dsh}（也接受 upstream:"host:port"）。
        // 默认停用、无密码（password.<i> 未写即无）、clientHostTrust=false；
        // 行追加在 patch 行之后并落盘 upstreams.json（重启保留、序号稳定）。
        const n = normalizeUpstreamInput(payload?.label, payload?.upstream ?? payload, payload?.dsh === true);
        if (!n.ok) return rpcFail(n.reason);
        if (typeof addEntry !== 'function') return rpcFail('运行时新增不可用 | runtime add unavailable');
        for (let j = 0; j < entryDefs.length; j++) {
          if (!isVisibleEntry(j)) continue;
          if (entryDefs[j]?.host === n.host && entryDefs[j]?.port === n.port) {
            return rpcFail('该上游地址已存在 | upstream already exists');
          }
        }
        const idx = addEntry(n);
        entryState.disabled[idx] = true; // 默认停用，主人设好密码再打开
        saveEntryState();
        return rpcOk({ index: idx });
      }
      return rpcFail(`Unknown endpoint: ${endpoint}`);
    } catch (err) {
      log.error?.('dsh-web-pass: rpc %s failed | %s', endpoint, err?.message ?? err);
      return rpcFail(err?.message ?? String(err));
    }
  }, { authority: 'loopback' });
}

const name = 'dsh-web-pass';
const inject = ['connection', 'webServer'];

// ---- 密码哈希：自描述的 modular-crypt 风格 scrypt 串（参数内嵌，将来可平滑调强）----
const SCRYPT_LOG_N = 15; // N = 2^15 = 32768
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
const HASH_TAG = 'scrypt';
const _scrypt = promisify(scryptCb);

async function deriveScrypt(password, salt, keylen, n, r, p) {
  return _scrypt(password, salt, keylen, { N: n, r, p, maxmem: SCRYPT_MAXMEM });
}

async function hashPassword(password) {
  const salt = randomBytes(16).toString('base64');
  const key = await deriveScrypt(password, salt, SCRYPT_KEYLEN, 2 ** SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P);
  return [HASH_TAG, 2 ** SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, salt, key.toString('base64')].join(':');
}

async function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  // 环境变量场景兼容明文：timingSafeEqual 不允许长度不等，必须先比长度
  if (!stored.startsWith(HASH_TAG + ':')) {
    const a = Buffer.from(String(password));
    const b = Buffer.from(stored);
    return a.length === b.length && timingSafeEqual(a, b);
  }
  const fields = stored.split(':');
  if (fields.length !== 6 || fields[0] !== HASH_TAG) return false;
  const n = Number(fields[1]), r = Number(fields[2]), p = Number(fields[3]);
  const logN = Math.log2(n);
  if (!Number.isInteger(logN) || logN < 10 || logN > 24) return false; // 拒绝过弱/离谱参数
  if (!Number.isInteger(r) || r < 1 || !Number.isInteger(p) || p < 1) return false;
  let expected;
  try { expected = Buffer.from(fields[5], 'base64'); } catch { return false; }
  if (!expected || expected.length === 0) return false;
  try {
    const derived = await deriveScrypt(password, fields[4], expected.length, n, r, p);
    return timingSafeEqual(derived, expected);
  } catch { return false; }
}

// ---- 密码强度校验：规则表驱动（≥8 位 + 大小写 + 数字）----
const STRENGTH_RULES = [
  { test: (p) => p.length >= 8, reason: '密码至少需要 8 位' },
  { test: (p) => /[a-z]/.test(p), reason: '密码必须包含小写字母' },
  { test: (p) => /[A-Z]/.test(p), reason: '密码必须包含大写字母' },
  { test: (p) => /[0-9]/.test(p), reason: '密码必须包含数字' },
];

export function passwordStrength(p) {
  for (const rule of STRENGTH_RULES) {
    if (!rule.test(p)) return { ok: false, reason: rule.reason };
  }
  return { ok: true, reason: null };
}

// ---- 会话存储（内存 + JSONL 持久化，重启不掉会话）----
// v0.3.2 起 2 天滑动：TTL 2 天，每次鉴权时剩余不足 1 天即续到 now + 2 天
// （活跃用户不断线；写盘最多约 1 天 1 次/会话）。token 绑定上游条目 entry。
const SESSION_TTL_MS = 2 * 24 * 3600 * 1000;
const SESSION_RENEW_MS = SESSION_TTL_MS / 2;
const SESSION_TOKEN_BYTES = 24;

class SessionStore {
  constructor(path) {
    this.path = path;
    this.live = new Map(); // token -> { createdAt, expiresAt, entry }
    this._load();
  }
  _load() {
    try {
      const lines = readFileSync(this.path, 'utf8').split('\n').filter(Boolean);
      const now = Date.now();
      for (const line of lines) {
        try {
          const ev = JSON.parse(line);
          // 新词表 issue/revoke/purge；同时兼容旧文件里的 add/remove/clear
          if (ev.token && (ev.op === 'issue' || ev.op === 'add') && ev.expiresAt > now) {
            this.live.set(ev.token, {
              createdAt: ev.createdAt || 0,
              expiresAt: ev.expiresAt,
              entry: typeof ev.entry === 'number' ? ev.entry : 0, // 旧行无 entry 视为管理员条目
            });
          } else if (ev.token && (ev.op === 'revoke' || ev.op === 'remove')) {
            this.live.delete(ev.token);
          } else if (Array.isArray(ev.tokens) && ev.op === 'remove-many') { // 旧词表：批量吊销
            for (const t of ev.tokens) this.live.delete(t);
          } else if (ev.op === 'purge' || ev.op === 'clear') {
            this.live.clear();
          }
        } catch {}
      }
      this._compact(); // 启动即压实，顺带把旧词表改写成新词表
    } catch {}
  }
  _append(ev) {
    try { ensureDataDir(); appendFileSync(this.path, JSON.stringify(ev) + '\n', { mode: 0o600 }); } catch {}
  }
  _compact() {
    try {
      ensureDataDir();
      const now = Date.now();
      const lines = [];
      for (const [token, s] of this.live) {
        if (s.expiresAt > now) lines.push(JSON.stringify({ op: 'issue', token, ...s }));
      }
      // 原子写：先写临时文件再 rename，避免进程中断把 sessions.jsonl 截断损坏
      const tmp = this.path + '.tmp';
      writeFileSync(tmp, lines.join('\n') + (lines.length ? '\n' : ''), { mode: 0o600 });
      renameSync(tmp, this.path);
    } catch {}
  }
  create(entry = 0) {
    const token = randomBytes(SESSION_TOKEN_BYTES).toString('hex');
    const sess = { createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS, entry };
    this.live.set(token, sess);
    this._append({ op: 'issue', token, ...sess });
    return token;
  }
  /** 校验会话：有效返回 {entry, renewed}（renewed=true 表示本次刚滑动续期），无效返回 null。 */
  verify(token) {
    if (!token) return null;
    const now = Date.now();
    const s = this.live.get(token);
    if (!s) return null;
    if (typeof s.entry !== 'number') s.entry = 0;
    if (s.expiresAt <= now) {
      this.live.delete(token);
      this._append({ op: 'revoke', token });
      return null;
    }
    let renewed = false;
    if (s.expiresAt - now < SESSION_RENEW_MS) {
      s.expiresAt = now + SESSION_TTL_MS;
      this._append({ op: 'issue', token, createdAt: s.createdAt, expiresAt: s.expiresAt, entry: s.entry });
      renewed = true;
    }
    return { entry: s.entry, renewed };
  }
  destroy(token) {
    this.live.delete(token);
    this._append({ op: 'revoke', token });
  }
  destroyAllExcept(keep) {
    for (const k of [...this.live.keys()]) {
      if (k !== keep) { this.live.delete(k); this._append({ op: 'revoke', token: k }); }
    }
  }
  /** 吊销某一条目（上游）的全部会话：改密码/停用/删除条目时调用。 */
  destroyEntrySessions(entry) {
    for (const [k, s] of [...this.live]) {
      if ((s.entry ?? 0) === entry) { this.live.delete(k); this._append({ op: 'revoke', token: k }); }
    }
  }
  destroyAll() { this.live.clear(); this._append({ op: 'purge' }); }
}

// ---- 数据目录与密码文件（多条目：条目 0 沿用老 `password` 文件，其它用 `password.<i>`）----
function dshHome() { return process.env.DSH_HOME ?? join(homedir(), '.dsh'); }
function dataDir() { return join(dshHome(), 'dsh-web-pass'); }
function passwordPath(entry = 0) { return entry === 0 ? join(dataDir(), 'password') : join(dataDir(), `password.${entry}`); }
function sessionsPath() { return join(dataDir(), 'sessions.jsonl'); }
function entryStatePath() { return join(dataDir(), 'entries.json'); }
function runtimeUpstreamsPath() { return join(dataDir(), 'upstreams.json'); }
function ensureDataDir() { try { mkdirSync(dataDir(), { recursive: true }); } catch {} }

/**
 * 上游条目表（密码→后端映射）。条目 0 恒为管理员（老 DSH），不可停用/删除。
 * 未配 upstreams 时退化为 v0.3.x 单条目（行为完全一致，零迁移）。
 * 每条：{ label, passwordEnv|null, host, port, clientHostTrust, dsh, enabled }
 */
let entryDefs = [];
/** 条目开关覆盖（即时生效，无需重起；0600 落盘）：{ disabled: {idx:true}, deleted: {idx:true} } */
let entryState = { disabled: {}, deleted: {} };

function loadEntryState() {
  entryState = { disabled: {}, deleted: {} };
  try {
    const raw = JSON.parse(readFileSync(entryStatePath(), 'utf8'));
    if (raw && typeof raw === 'object') {
      if (raw.disabled && typeof raw.disabled === 'object') entryState.disabled = raw.disabled;
      if (raw.deleted && typeof raw.deleted === 'object') entryState.deleted = raw.deleted;
    }
  } catch {}
}
function saveEntryState() {
  try { ensureDataDir(); writeFileSync(entryStatePath(), JSON.stringify(entryState), { mode: 0o600 }); } catch {}
}

export function resolveEntries(config = {}, dshPort, clientHostTrustDefault) {
  if (clientHostTrustDefault === undefined) clientHostTrustDefault = config.clientHostTrust !== false;
  const list = [{
    label: '管理员/admin',
    passwordEnv: (typeof config.passwordEnv === 'string' && config.passwordEnv) ? config.passwordEnv : 'DSH_WEB_PASS_PASSWORD',
    host: '127.0.0.1',
    port: dshPort,
    clientHostTrust: clientHostTrustDefault,
    dsh: true,
    enabled: true,
  }];
  const extra = Array.isArray(config.upstreams) ? config.upstreams : [];
  for (let i = 0; i < extra.length; i++) {
    const u = extra[i] ?? {};
    const port = Number(u.port);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) continue; // 坏行跳过，不炸进程
    list.push({
      label: String(u.label ?? '').trim() || `上游${i + 1}`,
      passwordEnv: (typeof u.passwordEnv === 'string' && u.passwordEnv) ? u.passwordEnv : null,
      host: String(u.host ?? '').trim() || '127.0.0.1',
      port,
      clientHostTrust: u.clientHostTrust === true, // 附加条目默认关（访客 DSH 等需要时再开）
      dsh: u.dsh === true, // 默认不代持/不改写（防把 DSH cookie 带给 openclaw 等第三方）；访客 DSH 请设 true
      enabled: u.enabled !== false,
    });
  }
  return list;
}

export function isKnownEntry(i) { return Number.isInteger(i) && i >= 0 && i < entryDefs.length; }
export function isVisibleEntry(i) { return isKnownEntry(i) && !entryState.deleted?.[i]; }
/** 条目是否可用：管理员恒开；其它看配置 + 开关覆盖（停用/删除即刻踢会话）。 */
export function isEnabledEntry(i) {
  if (!isVisibleEntry(i)) return false;
  if (i === 0) return true;
  if (entryDefs[i]?.enabled === false) return false;
  return !entryState.disabled?.[i];
}

/**
 * 设置页「新增上游」表单输入归一化（服务端与测试共用）。
 * upstream 可为 "host:port" / ":port" / "port" 字符串或 {host,port}；
 * host 缺省 127.0.0.1；标签滤引号/反斜杠/换行（防日志串行），≤32 字符。
 */
export function normalizeUpstreamInput(label, upstream, dsh = false) {
  const cleanLabel = String(label ?? '').replace(/[\r\n"\\]/g, '').trim();
  if (!cleanLabel) return { ok: false, reason: '请填写标签 | label required' };
  if (cleanLabel.length > 32) return { ok: false, reason: '标签过长（≤32 字符）| label too long' };
  let host = '';
  let port = NaN;
  if (typeof upstream === 'string') {
    const s = upstream.trim();
    if (!s) return { ok: false, reason: '请填写上游地址 | upstream required' };
    const i = s.lastIndexOf(':');
    if (i >= 0) { host = s.slice(0, i).trim(); port = Number(s.slice(i + 1).trim()); }
    else { port = Number(s); }
  } else if (upstream && typeof upstream === 'object') {
    host = String(upstream.host ?? '').trim();
    port = Number(upstream.port);
  }
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return { ok: false, reason: '端口无效（1-65535）| invalid port' };
  host = host || '127.0.0.1';
  if (!/^[A-Za-z0-9.\-]{1,253}$/.test(host)) return { ok: false, reason: 'host 仅支持 IP/域名 | host must be IP or hostname' };
  return { ok: true, label: cleanLabel, host, port, dsh: dsh === true };
}

/** 运行时条目（设置页新增）追加到 patch 条目之后：追加保序，序号即会话绑定键。 */
export function appendRuntimeEntries(defs, rows) {
  const out = defs.slice();
  for (const r of rows ?? []) {
    if (!r || typeof r !== 'object') continue;
    out.push({
      label: r.label,
      passwordEnv: null, // UI 行无环境变量，密码走 password.<i> 文件
      host: r.host,
      port: r.port,
      clientHostTrust: false,
      dsh: r.dsh === true,
      enabled: true,
    });
  }
  return out;
}

function readPasswordHash(entry = 0) {
  try { const p = readFileSync(passwordPath(entry), 'utf8').trim(); if (p) return p; } catch {}
  return null;
}
function writePasswordHash(entry, h) {
  ensureDataDir();
  writeFileSync(passwordPath(entry), h, { mode: 0o600 });
}

// 返回某条目当前密码的哈希或环境变量原文（null = 未设置）
function getPasswordSource(entry = 0) {
  const envName = entryDefs[entry]?.passwordEnv;
  if (envName) {
    const e = String(process.env[envName] ?? '').trim();
    if (e) return e; // 环境变量：原文
  }
  return readPasswordHash(entry); // 文件：scrypt 哈希 或 null
}

// ---- 选局域网 IP ----
function selectLanIPv4() {
  const ifaces = networkInterfaces();
  const cands = [];
  for (const [n, addrs] of Object.entries(ifaces)) {
    for (const a of addrs ?? []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      const ip = a.address;
      if (!ip || ip.startsWith('127.') || ip.startsWith('169.254.')) continue;
      let score = 0;
      if (/^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(ip)) score += 100;
      if (/^(?:wlan|wi-?fi|ethernet|eth\d|en\d|wlp\d|以太网|本地连接)/i.test(n)) score += 20;
      else if (/(radmin|tailscale|zerotier|tun|tap|vpn|vethernet|virtual|vmware|virtualbox|wsl|docker|teredo|hamachi|bluetooth|bridge)/i.test(n)) score -= 50;
      cands.push({ ip, score, order: cands.length });
    }
  }
  cands.sort((a, b) => b.score - a.score || a.order - b.order);
  return cands[0]?.ip ?? null;
}

export function apply(ctx, config = {}, internals = {}) {
  try {
    const logger = ctx.logger?.(name) ?? console;
    const dshPort = internals.dshPort ?? ctx.webServer?.port;
    if (!dshPort) { logger.warn('dsh-web-pass: 拿不到 dsh web 端口，跳过'); return () => {}; }

    const port = internals.port ?? config.port ?? 3081;
    // 是否信任 X-Forwarded-For / CF-Connecting-IP（仅网关前有可信反代时开启）
    const trustProxy = config.trustProxy === true;
    // 非 loopback 页面也启用 Host 设置文档（默认开，clientHostTrust: false 关闭；仅作用于管理员条目）
    const clientHostTrust = config.clientHostTrust !== false;
    ensureDataDir();
    loadEntryState();
    // 设置页新增的运行时条目（upstreams.json，0600）：追加在 patch 行之后，
    // 序号即会话绑定键——只追加/软删，绝不移动既有序号；重启原序重载。
    let runtimeRows = [];
    const loadRuntimeUpstreams = () => {
      runtimeRows = [];
      try {
        const raw = JSON.parse(readFileSync(runtimeUpstreamsPath(), 'utf8'));
        if (Array.isArray(raw?.entries)) {
          for (const r of raw.entries) {
            if (!r || typeof r !== 'object') continue;
            const p = Number(r.port);
            if (!Number.isInteger(p) || p <= 0 || p > 65535) continue;
            runtimeRows.push({
              label: String(r.label ?? '').replace(/[\r\n"\\]/g, '').trim() || '上游',
              host: String(r.host ?? '').trim() || '127.0.0.1',
              port: p,
              dsh: r.dsh === true,
              deleted: r.deleted === true,
            });
          }
        }
      } catch {}
    };
    const saveRuntimeUpstreams = () => {
      try { ensureDataDir(); writeFileSync(runtimeUpstreamsPath(), JSON.stringify({ version: 1, entries: runtimeRows }), { mode: 0o600 }); } catch {}
    };
    loadRuntimeUpstreams();
    // 上游条目表（密码→后端映射；条目 0 = 管理员老 DSH）
    entryDefs = resolveEntries(config, dshPort, clientHostTrust);
    const runtimeBase = entryDefs.length; // 运行时行起始序号（1 + patch 行数）
    entryDefs = appendRuntimeEntries(entryDefs, runtimeRows);

    // 会话存储（持久化到磁盘，重启不掉线）
    const sessions = new SessionStore(sessionsPath());

    // 构建 auth 接口供 proxy.mjs 使用（多条目：会话绑定条目，分流/吊销按条目）
    const auth = {
      getPasswordSource: (i = 0) => getPasswordSource(i),
      hasAnyPassword: () => entryDefs.some((_, i) => isEnabledEntry(i) && !!getPasswordSource(i)),
      // 验证某条目的明文密码
      verify: async (i, plaintext) => {
        const src = getPasswordSource(i);
        if (!src) return false;
        return verifyPassword(plaintext, src);
      },
      // 按顺序试所有可用条目，命中返回条目号，否则 -1（报错保持笼统，不透露哪条）
      verifyAny: async (plaintext) => {
        for (let i = 0; i < entryDefs.length; i++) {
          if (!isEnabledEntry(i)) continue;
          try {
            if (await verifyPassword(plaintext, getPasswordSource(i))) return i;
          } catch {}
        }
        return -1;
      },
      // 新密码是否与其它条目的环境变量明文撞车（文件哈希比不了，只拦能拦的）
      clashes: async (i, plaintext) => {
        for (let j = 0; j < entryDefs.length; j++) {
          if (j === i || !isVisibleEntry(j)) continue;
          const envName = entryDefs[j]?.passwordEnv;
          if (!envName) continue;
          const other = String(process.env[envName] ?? '').trim();
          if (other && other === plaintext) return true;
        }
        return false;
      },
      // 设置某条目新密码（哈希后写盘）；调用方负责吊销该条目会话
      setPasswordHash: async (i, plaintext) => {
        const h = await hashPassword(plaintext);
        writePasswordHash(i, h);
      },
      // 会话管理（verifySession 含滑动续期；停用/删除的条目会话即刻失效）
      createSession: (entry = 0) => sessions.create(entry),
      verifySession: (token) => {
        const r = sessions.verify(token);
        if (!r) return null;
        if (!isEnabledEntry(r.entry)) return null;
        return r;
      },
      sessionEntryOf: (req) => {
        try {
          const t = parseCookies(req.headers?.cookie)[SESSION_COOKIE];
          const r = t ? sessions.verify(t) : null;
          return r && isEnabledEntry(r.entry) ? r.entry : -1;
        } catch { return -1; }
      },
      destroySession: (token) => sessions.destroy(token),
      destroyEntrySessions: (entry) => sessions.destroyEntrySessions(entry),
      destroyAllExcept: (keep) => sessions.destroyAllExcept(keep),
      destroyAll: () => sessions.destroyAll(),
      isKnown: isKnownEntry,
      isVisible: isVisibleEntry,
      isEnabled: isEnabledEntry,
      setEnabled: (i, en) => { if (en) delete entryState.disabled[i]; else entryState.disabled[i] = true; saveEntryState(); },
      setDeleted: (i, del) => { if (del) entryState.deleted[i] = true; else delete entryState.deleted[i]; saveEntryState(); },
    };

    // 访问日志：按大小轮转（单文件超过 logMaxBytes 滚动为 .1/.2/…，最多保留 logMaxFiles 份）。
    // 不配置即用内置默认（1MB × 7 份）；cordis.patch.yml 被其他插件安装覆盖也不影响运行。
    const logPort = internals.logViewerPort ?? config.logViewerPort ?? 3082;
    const accessFile = join(dataDir(), 'access.log');
    const accessLogger = createAccessLogger({
      file: accessFile,
      maxBytes: config.logMaxBytes,
      maxFiles: config.logMaxFiles,
      trustProxy,
    });

    let proxy = null;
    let logViewer = null;
    const disposers = [];
    const dshStops = [];

    // 代持 DSH 内置 BrowserAuth：按 dsh:true 的条目各持一份（cookie 按上游 authority 绑定，不能共用）。
    // 非 DSH 条目（openclaw 等）不代持、不改写，原样透传。
    const dshProviders = new Map();
    for (let i = 0; i < entryDefs.length; i++) {
      const e = entryDefs[i];
      if (!e.dsh) continue;
      const p = new DshAuthProvider(ctx.connection, { host: e.host, port: e.port });
      p.log = logger;
      if (p.available()) {
        dshProviders.set(i, p);
        dshStops.push(p.start());
      }
    }
    if (dshProviders.size > 0) {
      logger.info('dsh-web-pass: DSH 内置认证代持已启用（connection.authenticatedUrl，共 %d 条上游）', dshProviders.size);
    } else {
      logger.warn('dsh-web-pass: ctx.connection 不可用，不代持 DSH 认证；浏览器仍需 DSH token');
    }
    const getDshAuth = (i) => dshProviders.get(i) ?? null;

    // 设置页「新增上游」：追加行 + 落盘 + 即场建代持（dsh:true 时），无需重起。
    const addEntry = (n) => {
      runtimeRows.push({ label: n.label, host: n.host, port: n.port, dsh: n.dsh, deleted: false });
      saveRuntimeUpstreams();
      entryDefs = appendRuntimeEntries(entryDefs, [n]);
      const idx = entryDefs.length - 1;
      if (n.dsh) {
        const p = new DshAuthProvider(ctx.connection, { host: n.host, port: n.port });
        p.log = logger;
        if (p.available()) {
          dshProviders.set(idx, p);
          dshStops.push(p.start());
        }
      }
      return idx;
    };
    // UI 删除运行时行：entries.json 软删之外，行内也标 deleted（index 稳定，重启保留隐藏）。
    const onEntryDeleted = (idx) => {
      const r = runtimeRows[idx - runtimeBase];
      if (r && idx >= runtimeBase) { r.deleted = true; saveRuntimeUpstreams(); }
    };

    const getStatus = async () => {
      const lan = selectLanIPv4();
      const proxyPort = proxy?.port ?? null;
      const lanUrl = lan && proxyPort ? `http://${lan}:${proxyPort}` : null;
      const entries = await Promise.all(entryDefs.map(async (e, i) => ({
        label: e.label,
        host: e.host,
        port: e.port,
        enabled: isEnabledEntry(i),
        visible: isVisibleEntry(i),
        reachable: isVisibleEntry(i) ? await probeTcp(e.host, e.port, 1200) : false,
        holding: !!dshProviders.get(i)?.cookie,
      })));
      return {
        proxyRunning: proxy !== null, proxyPort, lanUrl, lanQr: null,
        dshPort, logViewerPort: logViewer?.port ?? null,
        dshAuthHolding: !!dshProviders.get(0)?.cookie,
        entries,
      };
    };

    try { disposers.push(installGateRpc(ctx, { auth, getStatus, addEntry, onEntryDeleted, log: logger })); }
    catch (e) { logger.error('dsh-web-pass: RPC 注册失败(已忽略) | %s', e?.message ?? e); }

    void createLogViewer({ file: accessFile, port: logPort }).then((v) => {
      logViewer = v;
      logger.info('dsh-web-pass: 日志查看器已就绪 :%d | log viewer ready', v.port);
    }).catch((err) => {
      logger.error('dsh-web-pass: 日志查看器启动失败(已忽略) | %s', err?.message ?? err);
    });

    void createGateProxy({
      port, host: '0.0.0.0',
      upstreams: entryDefs.map((e) => ({ host: e.host, port: e.port, clientHostTrust: e.clientHostTrust })),
      getUpstreams: () => entryDefs.map((e) => ({ host: e.host, port: e.port, clientHostTrust: e.clientHostTrust })),
      getDshAuth,
      injectHtml: DEFAULT_INJECT, auth,
      maxLoginAttempts: config.maxLoginAttempts,
      loginLockMs: config.loginLockMs,
      trustProxy,
      onAccess: (req, res) => {
        if (['/gate-login', '/gate/setup', '/gate/logout'].includes(req.url)) {
          let label = '';
          try {
            const entry = auth.sessionEntryOf(req);
            if (entry >= 0) label = entryDefs[entry]?.label ?? '';
          } catch {}
          accessLogger.log(req, res, label).catch(() => {});
        }
      },
    }).then((p) => {
      proxy = p;
      logger.info('dsh-web-pass: 代理已就绪 :%d | proxy ready', p.port);
    }).catch((err) => {
      logger.error('dsh-web-pass: 代理启动失败 | %s', err?.message ?? err);
    });

    try {
      ctx.effect(() => async () => {
        for (const stop of dshStops.splice(0)) { try { stop(); } catch {} }
        for (const d of disposers.reverse()) { try { d(); } catch {} }
        if (logViewer) await logViewer.close();
        if (proxy) await proxy.close();
      }, 'dsh-web-pass: stop proxy & log viewer');
    } catch (e) { logger.error('dsh-web-pass: ctx.effect 失败(已忽略) | %s', e?.message ?? e); }

    return () => {};
  } catch (err) {
    try { console.error('[dsh-web-pass] apply 异常(已吞掉, 不影响 dsh web):', err); } catch {}
    return () => {};
  }
}

export { name, inject, SessionStore, SESSION_TTL_MS, SESSION_RENEW_MS };

/** 测试钩子：直接装配条目表 + 开关覆盖（生产代码仅 apply() 写这两处）。 */
export function setEntriesForTest(defs, state = { disabled: {}, deleted: {} }) {
  entryDefs = defs;
  entryState = { disabled: { ...(state.disabled ?? {}) }, deleted: { ...(state.deleted ?? {}) } };
}
