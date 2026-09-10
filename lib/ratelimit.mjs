// dsh-web-pass 登录防爆破限速器（v0.3.5 从 proxy.mjs 抽离）。
// 语义：per-IP 失败计数，成功登录不清零；累计达上限进入真锁定，
// 自最后一次失败起锁满 loginLockMs×退避倍数（每次触发翻倍，至多 16×）。
// 退避倍数在锁到期后保留（静默 RESET_IDLE_MS 无失败才回到 1×），否则到期即清零
// 会让退避永不生效（锁定期内请求直接 401 不计失败）。锁定期内的试探不计失败、
// 不延长锁定——防止攻击者借此把同 IP 受害者无限续锁。XFF 默认不信任
//（trustProxy=false 只看 socket 地址）。

const MULT_MAX = 16; // 退避倍数上限：16×（默认 60s 锁 → 最多 16 分钟）
const RESET_IDLE_MS = 60 * 60 * 1000; // 静默 1 小时无失败 → 退避倍数回到 1×（干净开局）

export function createGateRateLimiter({ trustProxy = false, maxLoginAttempts = 3, loginLockMs = 60_000, mapMax = 10_000 } = {}) {
  // ip -> { hits:number[], lockedUntil:number, mult:number, coolSince:number }
  const failuresByIp = new Map();
  const LOCK_BASE_MS = Math.max(1000, Number(loginLockMs) || 60_000); // 下限 1s 防误配
  const MAX_ATTEMPTS = Math.max(1, Number(maxLoginAttempts) || 3); // 下限 1：配 0/负数不再全员永久锁死

  function failKey(req) {
    if (!trustProxy) return req.socket?.remoteAddress ?? '?'; // 默认只信 socket 直连地址，XFF 可伪造
    const xff = String(req.headers['x-forwarded-for'] ?? '').split(',')[0]?.trim();
    // 截断到 64 字符（任何 IP 文本都够用），防止超长 XFF 头作为 Map key 撑内存
    return (xff && xff !== 'unknown') ? xff.slice(0, 64) : (req.socket?.remoteAddress ?? '?');
  }

  // 锁到期只清 hits/lockedUntil、保留 mult（记 coolSince）；长静默才整行删除。
  function settle(st, now) {
    if (st.lockedUntil && st.lockedUntil <= now) {
      st.coolSince = st.lockedUntil; // 冷却从锁实际结束时刻起算，而非首次观察到过期时
      st.lockedUntil = 0;
      st.hits = [];
    }
    if (st.coolSince && now - st.coolSince > RESET_IDLE_MS) {
      failuresByIp.delete(st.ip);
      return null;
    }
    return st;
  }

  function lockRemainingMs(ip) {
    if (!ip) return 0;
    const st = failuresByIp.get(ip);
    if (!st) return 0;
    const now = Date.now();
    if (settle(st, now) && st.lockedUntil > now) return st.lockedUntil - now;
    return 0;
  }

  function isRateLimited(ip) { return lockRemainingMs(ip) > 0; }

  function recordFailure(ip) {
    if (!ip) return;
    while (failuresByIp.size >= mapMax) { // 简单 FIFO 淘汰，防（伪造）海量 key 撑爆内存
      const first = failuresByIp.keys().next().value;
      if (first === undefined) break;
      failuresByIp.delete(first);
    }
    const now = Date.now();
    let st = failuresByIp.get(ip);
    if (!st) { st = { ip, hits: [], lockedUntil: 0, mult: 1, coolSince: 0 }; failuresByIp.set(ip, st); }
    else if (!settle(st, now)) {
      st = { ip, hits: [], lockedUntil: 0, mult: 1, coolSince: 0 };
      failuresByIp.set(ip, st);
    }
    if (st.lockedUntil > now) return; // 锁定期内试探不计、不延长（调用方本就提前 401）
    st.hits = st.hits.filter((t) => now - t < LOCK_BASE_MS);
    st.hits.push(now);
    if (st.hits.length >= MAX_ATTEMPTS) {
      st.lockedUntil = now + LOCK_BASE_MS * st.mult;
      st.mult = Math.min(st.mult * 2, MULT_MAX);
      st.hits = [];
      st.coolSince = 0;
    }
  }

  return { failKey, lockRemainingMs, isRateLimited, recordFailure };
}
