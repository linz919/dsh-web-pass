// dsh-web-pass · DSH 内置认证代持
// 与 DSH 同进程，通过 HostConnectionService.authenticatedUrl() 拿到
// launch-token URL，内部发起 GET 换取 DSH 的持久浏览器 cookie（303 + Set-Cookie），
// 之后把该 cookie 注入所有转发到上游的请求——浏览器只面对本密码门，
// 不再需要 DSH 的 token/cookie。

const DEFAULT_TTL_MS = 6 * 60 * 60 * 1000; // 每 6 小时强制重取一次（cookie 本身 30 天有效）
const PREWARM_DELAY_MS = 500;

export class DshAuthProvider {
  /** @param {object} connection - ctx.connection（HostConnectionService） */
  /** @param {{host:string, port:number}} upstream - DSH 上游地址 */
  constructor(connection, upstream) {
    this.connection = connection;
    this.upstream = upstream;
    this.cookie = null;          // "name=value"
    this.acquiredAt = 0;
    this.pending = null;         // 并发去重
    this.timer = null;
    this.log = typeof console !== 'undefined' ? console : { info() {}, warn() {}, error() {} };
  }

  baseUrl() {
    return `http://${this.upstream.host}:${this.upstream.port}/`;
  }

  available() {
    return !!this.connection && typeof this.connection.authenticatedUrl === 'function';
  }

  /** 立即取(缓存或现取)；失败返回 null，绝不抛出 */
  async get() {
    if (this.cookie && Date.now() - this.acquiredAt < DEFAULT_TTL_MS) return this.cookie;
    try {
      if (!this.pending) {
        this.pending = this.acquire()
          .finally(() => { this.pending = null; });
      }
      const cookie = await this.pending;
      return cookie || this.cookie;
    } catch (e) {
      this.log.warn?.('dsh-web-pass: 代持 DSH 认证获取失败(将保留旧值) | %s', e?.message ?? e);
      return this.cookie;
    }
  }

  /** 强制失效（下次 get 重新来往一次） */
  invalidate() { this.cookie = null; this.acquiredAt = 0; }

  async acquire() {
    if (!this.available()) return null;
    const tokenUrl = this.connection.authenticatedUrl(this.baseUrl());
    const res = await fetch(tokenUrl, {
      redirect: 'manual',          // 捕获 303，不跟随（跟随会丢 Set-Cookie）
      headers: { accept: 'text/html' },
      signal: AbortSignal.timeout(10_000),
    });
    // undici 提供 getSetCookie()；不用它时回退 headers.get('set-cookie')
    const setCookies = (typeof res.headers.getSetCookie === 'function')
      ? res.headers.getSetCookie()
      : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
    const nv = (setCookies[0] || '').split(';')[0]?.trim();
    if (!nv) {
      res.body?.cancel?.().catch?.(() => {});
      throw new Error(`未从 DSH 拿到 Set-Cookie（HTTP ${res.status}）`);
    }
    res.body?.cancel?.().catch?.(() => {});
    this.cookie = nv;
    this.acquiredAt = Date.now();
    this.log.info?.('dsh-web-pass: 已代持 DSH 浏览器 cookie（%s）', nv.split('=')[0]);
    return nv;
  }

  /** 启动预热 + 周期刷新（仅当 connection 可用） */
  start() {
    if (!this.available()) return () => {};
    const prewarm = () => { void this.get().catch(() => {}); };
    const t1 = setTimeout(prewarm, PREWARM_DELAY_MS);
    const t2 = setInterval(() => { this.invalidate(); prewarm(); }, DEFAULT_TTL_MS);
    return () => { clearTimeout(t1); clearInterval(t2); };
  }
}