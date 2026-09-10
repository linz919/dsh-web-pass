// dsh-web-pass 会话存储（v0.3.5 从 index.js 抽离）：内存 Map + JSONL 持久化，重启不掉会话。
// v0.3.2 起 2 天滑动：TTL 2 天，每次鉴权时剩余不足 1 天即续到 now + 2 天
// （活跃用户不断线；写盘最多约 1 天 1 次/会话）。token 绑定上游条目 entry + 上游指纹 up。
import { readFileSync, writeFileSync, appendFileSync, renameSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { ensureDataDir } from './paths.mjs';

export const SESSION_TTL_MS = 2 * 24 * 3600 * 1000;
export const SESSION_RENEW_MS = SESSION_TTL_MS / 2;
const SESSION_TOKEN_BYTES = 24;

export class SessionStore {
  constructor(path, log = console) {
    this.path = path;
    this.log = log ?? console;
    this.live = new Map(); // token -> { createdAt, expiresAt, entry, up }
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
              up: typeof ev.up === 'string' ? ev.up : undefined, // 旧行无 up：verifySession 比对失败即吊销（升级后需重登一次）
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
    try { ensureDataDir(); appendFileSync(this.path, JSON.stringify(ev) + '\n', { mode: 0o600 }); return true; }
    catch (e) {
      // 落盘失败：立即全量压实重试一次；仍失败则大声记错——
      // revocation durability 不保证（重启后已吊销会话可能复活），属已知一致性边界，详见发布说明。
      // 不 fail-closed：磁盘瞬时异常时把全员踢下线，可用性代价远大于这个极低概率窗口。
      if (this._compact()) return true;
      try { this.log.error?.('dsh-web-pass: 会话落盘失败且压实重试未果，吊销持久化不保证(重启后已吊销会话可能复活) | %s', e?.message ?? e); } catch {}
      return false;
    }
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
      return true;
    } catch (e) {
      try { this.log.error?.('dsh-web-pass: 会话压实失败 | %s', e?.message ?? e); } catch {}
      return false;
    }
  }
  /** @param {number} entry 条目序号 @param {string} up 上游指纹 "host:port"（会话同时绑定序号与上游身份） */
  create(entry = 0, up = '') {
    const token = randomBytes(SESSION_TOKEN_BYTES).toString('hex');
    const sess = { createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS, entry, up };
    this.live.set(token, sess);
    this._append({ op: 'issue', token, ...sess });
    return token;
  }
  /** 校验会话：有效返回 {entry, up, renewed}（renewed=true 表示本次刚滑动续期），无效返回 null。 */
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
      this._append({ op: 'issue', token, createdAt: s.createdAt, expiresAt: s.expiresAt, entry: s.entry, up: s.up });
      renewed = true;
    }
    return { entry: s.entry, up: s.up, renewed };
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
