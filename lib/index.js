// dsh-web-pass 插件入口（v0.3.5 重构后仅保留「装配 + RPC 面」）：
// 领域模块拆分——paths（数据目录）/ passwords（scrypt+强度）/ session-store（会话）/
// entries（条目表）/ gate-pages（门页面）/ ratelimit（防爆破）/ accesslog / dsh-auth / proxy。
import { readFileSync, writeFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { join } from 'node:path';
import { createGateProxy, DEFAULT_INJECT, probeTcp, SESSION_COOKIE, parseCookies } from './proxy.mjs';
import { passwordStrength, hashPassword, verifyPassword, writePasswordHash } from './passwords.mjs';
import { dataDir, passwordPath, sessionsPath, runtimeUpstreamsPath, ensureDataDir } from './paths.mjs';
import { SessionStore, SESSION_TTL_MS, SESSION_RENEW_MS } from './session-store.mjs';
import {
  setEntryDefs, getEntryDefs, loadEntryState, saveEntryState,
  setEntryEnabled, setEntryDeleted,
  resolveEntries, isKnownEntry, isVisibleEntry, isEnabledEntry,
  normalizeUpstreamInput, appendRuntimeEntries, setEntriesForTest,
} from './entries.mjs';
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

// 对外 API 兼容（v0.3.5 起实现移至领域模块，此处保持导出面不变）
export { SessionStore, SESSION_TTL_MS, SESSION_RENEW_MS };
export { passwordStrength, hashPassword, verifyPassword };
export { resolveEntries, isKnownEntry, isVisibleEntry, isEnabledEntry, normalizeUpstreamInput, appendRuntimeEntries, setEntriesForTest };

function rpcOk(value) { return { ok: true, value }; }
function rpcFail(message) { return { ok: false, error: { code: 'bad-request', message, details: { issues: [{ message }] } } }; }

function installGateRpc(ctx, { auth, getStatus, addEntry = null, onEntryDeleted = null, log = console } = {}) {
  if (!ctx?.connection?.rpc?.handle) {
    log.warn?.('dsh-web-pass: Connection RPC unavailable — 设置页不可用');
    return () => {};
  }
  // 注：v0.3.4 及以前曾传第三参 { authority: 'loopback' }——经审计核对 DSH 实现
  //（dsh-client-connection rpc.handle 只接受 (channel, handler)），该选项被静默忽略，
  // 并不提供「仅本机可调」限制，故移除，避免错觉。RPC 的实际保护来自 DSH 的
  // 浏览器认证（Host/Origin 检查 + token）与「通道仅注册在管理员 DSH 进程」的拓扑。
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
        for (let j = 0; j < getEntryDefs().length; j++) {
          if (!isVisibleEntry(j)) continue;
          if (getEntryDefs()[j]?.host === n.host && getEntryDefs()[j]?.port === n.port) {
            return rpcFail('该上游地址已存在 | upstream already exists');
          }
        }
        const idx = addEntry(n);
        setEntryEnabled(idx, false); // 默认停用，主人设好密码再打开
        return rpcOk({ index: idx });
      }
      return rpcFail(`Unknown endpoint: ${endpoint}`);
    } catch (err) {
      log.error?.('dsh-web-pass: rpc %s failed | %s', endpoint, err?.message ?? err);
      return rpcFail(err?.message ?? String(err));
    }
  });
}

const name = 'dsh-web-pass';
const inject = ['connection', 'webServer'];

// 返回某条目当前密码的哈希或环境变量原文（null = 未设置）
function getPasswordSource(entry = 0) {
  const envName = getEntryDefs()[entry]?.passwordEnv;
  if (envName) {
    const e = String(process.env[envName] ?? '').trim();
    if (e) return e; // 环境变量：原文
  }
  try { const p = readFileSync(passwordPath(entry), 'utf8').trim(); if (p) return p; } catch {}
  return null; // 文件：scrypt 哈希 或 null
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
      try { ensureDataDir(); writeFileSync(runtimeUpstreamsPath(), JSON.stringify({ version: 1, entries: runtimeRows }), { mode: 0o600 }); }
      catch (e) { try { logger.error('dsh-web-pass: upstreams.json 落盘失败(磁盘满/只读?) | %s', e?.message ?? e); } catch {} }
    };
    loadRuntimeUpstreams();
    // 上游条目表（密码→后端映射；条目 0 = 管理员老 DSH）
    setEntryDefs(resolveEntries(config, dshPort, clientHostTrust, (m) => logger.warn(m)));
    const runtimeBase = getEntryDefs().length; // 运行时行起始序号（1 + patch 行数）
    setEntryDefs(appendRuntimeEntries(getEntryDefs(), runtimeRows));

    // 会话存储（持久化到磁盘，重启不掉线）
    const sessions = new SessionStore(sessionsPath(), logger);
    // 上游身份指纹：会话同时绑定条目序号与上游 host:port——patch 删行/重排并重启后，
    // 旧会话不会静默重绑到同序号的新上游（v0.3.5 审计确认的重绑路径），直接作废。
    const upKeyOf = (i) => { const e = getEntryDefs()[i]; return e ? `${e.host}:${e.port}` : ''; };

    // 构建 auth 接口供 proxy.mjs 使用（多条目：会话绑定条目，分流/吊销按条目）
    const auth = {
      getPasswordSource: (i = 0) => getPasswordSource(i),
      hasAnyPassword: () => getEntryDefs().some((_, i) => isEnabledEntry(i) && !!getPasswordSource(i)),
      // 验证某条目的明文密码
      verify: async (i, plaintext) => {
        const src = getPasswordSource(i);
        if (!src) return false;
        return verifyPassword(plaintext, src);
      },
      // 按顺序试所有可用条目，命中返回条目号，否则 -1（报错保持笼统，不透露哪条）
      verifyAny: async (plaintext) => {
        for (let i = 0; i < getEntryDefs().length; i++) {
          if (!isEnabledEntry(i)) continue;
          try {
            if (await verifyPassword(plaintext, getPasswordSource(i))) return i;
          } catch {}
        }
        return -1;
      },
      // 新密码是否与其它条目的环境变量明文撞车（文件哈希比不了，只拦能拦的）
      clashes: async (i, plaintext) => {
        for (let j = 0; j < getEntryDefs().length; j++) {
          if (j === i || !isVisibleEntry(j)) continue;
          const envName = getEntryDefs()[j]?.passwordEnv;
          if (!envName) continue;
          const other = String(process.env[envName] ?? '').trim();
          if (other && other === plaintext) return true;
        }
        return false;
      },
      // 设置某条目新密码（哈希后写盘）；调用方负责吊销该条目会话
      setPasswordHash: async (i, plaintext) => {
        const h = await hashPassword(plaintext);
        writePasswordFile(i, h);
      },
      // 会话管理（verifySession 含滑动续期；停用/删除的条目会话即刻失效；
      // 上游地址与签发时不一致（patch 重排/改端口）→ 会话作废并吊销）
      createSession: (entry = 0) => sessions.create(entry, upKeyOf(entry)),
      verifySession: (token) => {
        const r = sessions.verify(token);
        if (!r) return null;
        if (!isEnabledEntry(r.entry)) { sessions.destroy(token); return null; }
        if (r.up !== upKeyOf(r.entry)) { sessions.destroy(token); return null; }
        return r;
      },
      sessionEntryOf: (req) => {
        try {
          const t = parseCookies(req.headers?.cookie)[SESSION_COOKIE];
          const r = t ? sessions.verify(t) : null;
          return r && isEnabledEntry(r.entry) && r.up === upKeyOf(r.entry) ? r.entry : -1;
        } catch { return -1; }
      },
      destroySession: (token) => sessions.destroy(token),
      destroyEntrySessions: (entry) => sessions.destroyEntrySessions(entry),
      destroyAllExcept: (keep) => sessions.destroyAllExcept(keep),
      destroyAll: () => sessions.destroyAll(),
      isKnown: isKnownEntry,
      isVisible: isVisibleEntry,
      isEnabled: isEnabledEntry,
      setEnabled: (i, en) => setEntryEnabled(i, en),
      setDeleted: (i, del) => setEntryDeleted(i, del),
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
    for (const [i, e] of getEntryDefs().entries()) {
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
      setEntryDefs(appendRuntimeEntries(getEntryDefs(), [n]));
      const idx = getEntryDefs().length - 1;
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
      const entries = await Promise.all(getEntryDefs().map(async (e, i) => ({
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

    // 条目分流表：静态快照（老调用兼容）与动态取值（运行时新增即时参与分流）共用同一份映射
    const routeRows = () => getEntryDefs().map((e) => ({ host: e.host, port: e.port, clientHostTrust: e.clientHostTrust }));
    void createGateProxy({
      port, host: '0.0.0.0',
      upstreams: routeRows(),
      getUpstreams: routeRows,
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
            if (entry >= 0) label = getEntryDefs()[entry]?.label ?? '';
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

export { name, inject };
