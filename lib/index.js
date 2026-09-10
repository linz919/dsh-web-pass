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
// v0.3.7: use DSH's shared authenticated /api RPC channel.
// The old private /dsh-web-pass channel remains only as a fallback.
export const GATE_RPC_CHANNEL = '/api';
export const LEGACY_GATE_RPC_CHANNEL = '/dsh-web-pass';
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
  if (!ctx?.connection?.rpc) {
    log.warn?.('dsh-web-pass: Connection RPC unavailable — 设置页不可用');
    return () => {};
  }
  // v0.3.7：不要占用 DSH 共享 /api 的唯一 interceptor 槽位。
  // 0.1.5-rc.1 的 API Gateway 也依赖这个共享入口；注册 interceptor 会
  // 让普通 /api（尤其 session list）无法继续落到 Gateway fallback。
  // 改用 Connection 的 exact Fetch route：每个 webpass endpoint 独占自己的
  // /api/<endpoint> 路径，既经过 Connection 的认证/Origin fence，又不拦截其它 API。
  const handler = async (endpoint, payload = {}) => {
    try {
      if (endpoint === GATE_ENDPOINTS.status) return rpcOk(await getStatus());
      if (endpoint === GATE_ENDPOINTS.passwordSet) {
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
        const idx = Number(payload?.entry);
        if (!Number.isInteger(idx) || idx <= 0 || !auth.isKnown(idx)) return rpcFail('未知条目 | unknown entry');
        const enabled = payload?.enabled !== false;
        auth.setEnabled(idx, enabled);
        if (!enabled) auth.destroyEntrySessions(idx);
        return rpcOk({ ok: true });
      }
      if (endpoint === GATE_ENDPOINTS.entryDel) {
        const idx = Number(payload?.entry);
        if (!Number.isInteger(idx) || idx <= 0 || !auth.isKnown(idx)) return rpcFail('未知条目 | unknown entry');
        auth.setDeleted(idx, true);
        auth.destroyEntrySessions(idx);
        try { onEntryDeleted?.(idx); } catch {}
        return rpcOk({ ok: true });
      }
      if (endpoint === GATE_ENDPOINTS.entryAdd) {
        const n = normalizeUpstreamInput(payload?.label, payload?.upstream ?? payload, payload?.dsh === true);
        if (!n.ok) return rpcFail(n.reason);
        if (typeof addEntry !== 'function') return rpcFail('运行时新增不可用 | runtime add unavailable');
        for (let j = 0; j < getEntryDefs().length; j++) {
          if (!isVisibleEntry(j)) continue;
          if (getEntryDefs()[j]?.host === n.host && getEntryDefs()[j]?.port === n.port) {
            return rpcFail('该上游地址已存在 | upstream already exists');
          }
        }
        log.info?.('dsh-web-pass: 新增上游请求 label=%s upstream=%s:%d dsh=%s', n.label, n.host, n.port, n.dsh);
        const idx = addEntry(n);
        if (!Number.isInteger(idx) || idx < 0 || !getEntryDefs()[idx] || getEntryDefs()[idx].host !== n.host || Number(getEntryDefs()[idx].port) !== n.port) {
          log.error?.('dsh-web-pass: 新增上游后校验失败 idx=%s host=%s port=%s', idx, n.host, n.port);
          return rpcFail(`新增后端校验失败：${n.host}:${n.port} 未写入条目表`);
        }
        setEntryEnabled(idx, false);
        log.info?.('dsh-web-pass: 新增上游成功 idx=%d %s:%d（默认停用）', idx, n.host, n.port);
        return rpcOk({ index: idx, entry: { label: n.label, host: n.host, port: n.port, dsh: n.dsh, enabled: false, visible: true, reachable: null, holding: false } });
      }
      return rpcFail(`Unknown endpoint: ${endpoint}`);
    } catch (err) {
      log.error?.('dsh-web-pass: rpc %s failed | %s', endpoint, err?.message ?? err);
      return rpcFail(err?.message ?? String(err));
    }
  };

  const rpc = ctx.connection.rpc;
  const fetchApi = ctx.connection.fetch;
  const endpoints = Object.values(GATE_ENDPOINTS);

  if (fetchApi?.register) {
    const disposers = [];
    for (const endpoint of endpoints) {
      const path = `/api/${endpoint}`;
      const dispose = fetchApi.register({
        path,
        methods: ['POST'],
        requestBody: 'buffered',
        fetch: async (request) => {
          if (request.method !== 'POST') return new Response('method not allowed', { status: 405 });
          let body;
          try { body = await request.json(); }
          catch { return new Response('body is not JSON', { status: 400 }); }
          const rpcId = typeof body?.rpcId === 'string' ? body.rpcId : 'dsh-web-pass-invalid-request';
          const method = body?.method;
          if (body?.type !== 'client-request' || method !== endpoint) {
            return Response.json({
              type: 'server-response',
              rpcId,
              result: { ok: false, error: { code: 'gateway/bad-request', message: 'invalid client-request message', details: {} } },
            });
          }
          const result = await handler(endpoint, body?.payload ?? {});
          return Response.json({ type: 'server-response', rpcId, result });
        },
      });
      disposers.push(dispose);
    }
    return async () => {
      for (const dispose of disposers.reverse()) {
        try { await dispose(); } catch {}
      }
    };
  }

  // Older Connection builds: preserve the original private channel as a compatibility fallback.
  if (typeof rpc.handle === 'function') return rpc.handle(LEGACY_GATE_RPC_CHANNEL, handler);
  log.warn?.('dsh-web-pass: Connection RPC unavailable — 设置页不可用');
  return () => {};
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
        writePasswordHash(i, h);
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
      // 先处理“曾经删除过、现在再次添加同一 host:port”的情况。
      // appendRuntimeEntries() 会按 host:port 去重；如果旧条目仍在内存表但
      // 被 entryState.deleted 标记，它也会被跳过，旧版因此误报
      // “运行时上游未加入内存条目表”。这里直接复用原序号并解除软删。
      const existing = getEntryDefs().findIndex((e) => e?.host === n.host && Number(e?.port) === n.port);
      if (existing >= 0) {
        if (existing < runtimeBase) {
          throw new Error(`该上游地址已由 patch 配置占用：${n.host}:${n.port}`);
        }
        const rr = runtimeRows[existing - runtimeBase];
        if (!rr) {
          throw new Error(`运行时条目状态不一致：${n.host}:${n.port}（缺少持久化行）`);
        }
        rr.label = n.label;
        rr.host = n.host;
        rr.port = n.port;
        rr.dsh = n.dsh === true;
        rr.deleted = false;
        saveRuntimeUpstreams();
        setEntryDeleted(existing, false);
        setEntryEnabled(existing, false);
        // 软删后重新启用 DSH 代持时，旧 provider 可能仍持有旧配置；
        // 非 DSH 复用原 provider 即可，DSH 则重新建立。
        if (n.dsh) {
          const old = dshProviders.get(existing);
          try { old?.stop?.(); } catch {}
          const p = new DshAuthProvider(ctx.connection, { host: n.host, port: n.port });
          p.log = logger;
          if (p.available()) {
            dshProviders.set(existing, p);
            dshStops.push(p.start());
          }
        } else {
          dshProviders.delete(existing);
        }
        logger.info?.('dsh-web-pass: 复用已存在运行时上游 idx=%d %s:%d（解除软删）', existing, n.host, n.port);
        return existing;
      }

      const before = getEntryDefs().length;
      const row = { label: n.label, host: n.host, port: n.port, dsh: n.dsh, deleted: false };
      runtimeRows.push(row);
      try { saveRuntimeUpstreams(); } catch (e) {
        runtimeRows.pop();
        throw new Error(`运行时上游保存失败：${e?.message ?? e}`);
      }

      // 新行必须直接追加；这里不再用 appendRuntimeEntries() 做二次去重，
      // 因为在上面的 existing 检查之后，重复只能代表内部状态发生了变化。
      const next = getEntryDefs().slice();
      next.push({
        label: n.label,
        passwordEnv: null,
        host: n.host,
        port: n.port,
        clientHostTrust: false,
        dsh: n.dsh === true,
        enabled: true,
      });
      setEntryDefs(next);
      const idx = before;
      if (!getEntryDefs()[idx] || getEntryDefs()[idx].host !== n.host || Number(getEntryDefs()[idx].port) !== n.port) {
        runtimeRows.pop();
        saveRuntimeUpstreams();
        throw new Error(`运行时上游未加入内存条目表：${n.host}:${n.port}`);
      }
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
