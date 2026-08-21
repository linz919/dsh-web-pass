// dsh-web-pass 插件入口：安全加固版
// 密码用 scrypt 哈希、会话用随机令牌（cookie ≠ 密码）、密码强度 ≥8 位+大小写+数字
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, renameSync } from 'node:fs';
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { join, dirname } from 'node:path';
import { homedir, networkInterfaces } from 'node:os';
import { promisify } from 'node:util';
import { createGateProxy, DEFAULT_INJECT } from './proxy.mjs';
import { createAccessLogger, createLogViewer } from './accesslog.mjs';

// ---- RPC 契约 ----
export const GATE_RPC_CHANNEL = '/dsh-web-pass';
export const GATE_ENDPOINTS = Object.freeze({
  status: 'webpass.status',
  passwordSet: 'webpass.password.set',
});

function rpcOk(value) { return { ok: true, value }; }
function rpcFail(message) { return { ok: false, error: { code: 'bad-request', message, details: { issues: [{ message }] } } }; }

function installGateRpc(ctx, { auth, getStatus, log = console } = {}) {
  if (!ctx?.connection?.rpc?.handle) {
    log.warn?.('dsh-web-pass: Connection RPC unavailable — 设置页不可用');
    return () => {};
  }
  return ctx.connection.rpc.handle(GATE_RPC_CHANNEL, async (endpoint, payload = {}) => {
    try {
      if (endpoint === GATE_ENDPOINTS.status) return rpcOk(await getStatus());
      if (endpoint === GATE_ENDPOINTS.passwordSet) {
        const pw = String(payload?.password ?? '').trim();
        const confirm = String(payload?.confirm ?? '').trim();
        const current = String(payload?.current ?? '').trim();
        const src = auth.getPasswordSource();
        if (src) {
          if (!current) return rpcFail('请输入当前密码 | current password required');
          if (!(await auth.verify(current))) return rpcFail('当前密码不正确 | current password is wrong');
        }
        if (!pw) return rpcFail('密码不能为空 | password required');
        const st = passwordStrength(pw);
        if (!st.ok) return rpcFail(st.reason);
        if (!confirm) return rpcFail('请再次输入确认密码 | confirmation required');
        if (pw !== confirm) return rpcFail('两次输入的密码不一致 | passwords do not match');
        await auth.setPasswordHash(pw);
        auth.destroyAllExcept(null);
        return rpcOk({ ok: true });
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

// ---- 会话存储（内存 + 可选 JSONL 持久化，重启不丢会话）----
const SESSION_TTL_MS = 24 * 3600 * 1000; // 默认 24 小时
const SESSION_TOKEN_BYTES = 24;

class SessionStore {
  constructor(path) {
    this.path = path;
    this.live = new Map(); // token -> { createdAt, expiresAt }
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
            this.live.set(ev.token, { createdAt: ev.createdAt || 0, expiresAt: ev.expiresAt });
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
  create() {
    const token = randomBytes(SESSION_TOKEN_BYTES).toString('hex');
    const sess = { createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS };
    this.live.set(token, sess);
    this._append({ op: 'issue', token, ...sess });
    return token;
  }
  verify(token) {
    if (!token) return false;
    const s = this.live.get(token);
    if (!s) return false;
    if (s.expiresAt <= Date.now()) { this.live.delete(token); return false; }
    return true;
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
  destroyAll() { this.live.clear(); this._append({ op: 'purge' }); }
}

// ---- 数据目录与密码文件 ----
function dshHome() { return process.env.DSH_HOME ?? join(homedir(), '.dsh'); }
function dataDir() { return join(dshHome(), 'dsh-web-pass'); }
function passwordPath() { return join(dataDir(), 'password'); }
function sessionsPath() { return join(dataDir(), 'sessions.jsonl'); }
function ensureDataDir() { try { mkdirSync(dataDir(), { recursive: true }); } catch {} }

let passwordEnvName = null;

function readPasswordHash() {
  try { const p = readFileSync(passwordPath(), 'utf8').trim(); if (p) return p; } catch {}
  return null;
}
function writePasswordHash(h) {
  ensureDataDir();
  writeFileSync(passwordPath(), h, { mode: 0o600 });
}

// 返回当前密码的哈希或环境变量原文（null = 未设置）
function getPasswordSource() {
  if (passwordEnvName) {
    const e = String(process.env[passwordEnvName] ?? '').trim();
    if (e) return e; // 环境变量：原文
  }
  return readPasswordHash(); // 文件：scrypt 哈希 或 null
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
    passwordEnvName = (typeof config.passwordEnv === 'string' && config.passwordEnv) ? config.passwordEnv : 'DSH_WEB_PASS_PASSWORD';
    // 是否信任 X-Forwarded-For / CF-Connecting-IP（仅网关前有可信反代时开启）
    const trustProxy = config.trustProxy === true;
    ensureDataDir();

    // 会话存储（持久化到磁盘，重启不掉线）
    const sessions = new SessionStore(sessionsPath());

    // 构建 auth 接口供 proxy.mjs 使用
    const auth = {
      // 获取密码哈希（null = 未设置 → 强制设置页）
      getPasswordSource,
      // 验证明文密码
      verify: async (plaintext) => {
        const src = getPasswordSource();
        if (!src) return false;
        return verifyPassword(plaintext, src);
      },
      // 设置新密码（哈希后写盘，无环境变量场景）
      setPasswordHash: async (plaintext) => {
        const h = await hashPassword(plaintext);
        writePasswordHash(h);
      },
      // 会话管理
      createSession: () => sessions.create(),
      verifySession: (token) => sessions.verify(token),
      destroySession: (token) => sessions.destroy(token),
      destroyAllExcept: (keep) => sessions.destroyAllExcept(keep),
      destroyAll: () => sessions.destroyAll(),
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

    const getStatus = async () => {
      const lan = selectLanIPv4();
      const proxyPort = proxy?.port ?? null;
      const lanUrl = lan && proxyPort ? `http://${lan}:${proxyPort}` : null;
      return { proxyRunning: proxy !== null, proxyPort, lanUrl, lanQr: null, dshPort, logViewerPort: logViewer?.port ?? null };
    };

    try { disposers.push(installGateRpc(ctx, { auth, getStatus, log: logger })); }
    catch (e) { logger.error('dsh-web-pass: RPC 注册失败(已忽略) | %s', e?.message ?? e); }

    void createLogViewer({ file: accessFile, port: logPort }).then((v) => {
      logViewer = v;
      logger.info('dsh-web-pass: 日志查看器已就绪 :%d | log viewer ready', v.port);
    }).catch((err) => {
      logger.error('dsh-web-pass: 日志查看器启动失败(已忽略) | %s', err?.message ?? err);
    });

    void createGateProxy({
      port, host: '0.0.0.0', upstream: { host: '127.0.0.1', port: dshPort },
      injectHtml: DEFAULT_INJECT, auth,
      maxLoginAttempts: config.maxLoginAttempts,
      loginLockMs: config.loginLockMs,
      trustProxy,
      onAccess: (req, res) => {
        if (['/gate-login', '/gate/setup', '/gate/logout'].includes(req.url))
          accessLogger.log(req, res).catch(() => {});
      },
    }).then((p) => {
      proxy = p;
      logger.info('dsh-web-pass: 代理已就绪 :%d | proxy ready', p.port);
    }).catch((err) => {
      logger.error('dsh-web-pass: 代理启动失败 | %s', err?.message ?? err);
    });

    try {
      ctx.effect(() => async () => {
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

export { name, inject };
