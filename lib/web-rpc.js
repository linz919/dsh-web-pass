// dsh-web-pass Web RPC（仅本机 loopback 可调）：设置页 ⇄ 代理（状态 / 改密码 / 随机换密码）
export const GATE_RPC_CHANNEL = '/dsh-web-pass';
export const GATE_ENDPOINTS = Object.freeze({
  status: 'webpass.status',
  passwordGet: 'webpass.password.get',
  passwordSet: 'webpass.password.set',
  passwordRandom: 'webpass.password.random',
});

function ok(value) { return { ok: true, value }; }
function fail(message) {
  return { ok: false, error: { code: 'bad-request', message, details: { issues: [{ message }] } } };
}

/** 生成随机强密码：字母+数字，保证至少含字母（不会纯数字）。 */
function randomPassword(len = 16) {
  // 去掉易混淆字符：0/o、1/l/I
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  for (let attempt = 0; attempt < 50; attempt++) {
    let s = '';
    for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
    if (/[A-Za-z]/.test(s)) return s; // 至少一个字母
  }
  // 兜底
  const letter = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  return Array.from({ length: len - 2 }, () => chars[Math.floor(Math.random() * chars.length)]).join('') +
    letter[Math.floor(Math.random() * letter.length)] + letter[Math.floor(Math.random() * letter.length)];
}

export function installGateRpc(ctx, { getPassword, setPassword, getStatus, log = console } = {}) {
  if (!ctx?.connection?.rpc?.handle) {
    log.warn?.('dsh-web-pass: Connection RPC unavailable — 设置页不可用');
    return () => {};
  }
  return ctx.connection.rpc.handle(GATE_RPC_CHANNEL, async (endpoint, payload = {}) => {
    try {
      if (endpoint === GATE_ENDPOINTS.status) return ok(await getStatus());
      if (endpoint === GATE_ENDPOINTS.passwordGet) return ok({ password: getPassword() });
      if (endpoint === GATE_ENDPOINTS.passwordSet) {
        const pw = String(payload?.password ?? '').trim();
        const confirm = String(payload?.confirm ?? '').trim();
        if (!pw) return fail('密码不能为空 | password required');
        if (/^\d+$/.test(pw)) return fail('密码不能是纯数字 | password must contain letters');
        if (!confirm) return fail('请再次输入确认密码 | confirmation required');
        if (pw !== confirm) return fail('两次输入的密码不一致 | passwords do not match');
        setPassword(pw);
        return ok({ ok: true });
      }
      if (endpoint === GATE_ENDPOINTS.passwordRandom) {
        const pw = randomPassword();
        setPassword(pw);
        return ok({ password: pw });
      }
      return fail(`Unknown endpoint: ${endpoint}`);
    } catch (err) {
      log.error?.('dsh-web-pass: rpc %s failed | %s', endpoint, err?.message ?? err);
      return fail(err?.message ?? String(err));
    }
  }, { authority: 'loopback' });
}
