// dsh-web-pass 上游条目表（v0.3.5 从 index.js 抽离）：密码→后端映射 + 开关覆盖 + 归一化。
// 条目 0 恒为管理员（老 DSH），不可停用/删除。未配 upstreams 时退化为单条目（零迁移）。
// 每条：{ label, passwordEnv|null, host, port, clientHostTrust, dsh, enabled }
import { readFileSync, writeFileSync } from 'node:fs';
import { entryStatePath, ensureDataDir } from './paths.mjs';

/** 上游条目表。序号 = 会话绑定键（只追加/软删保序，绝不移动既有序号）。 */
let entryDefs = [];
/** 条目开关覆盖（即时生效，无需重起；0600 落盘）：{ disabled: {idx:true}, deleted: {idx:true} } */
let entryState = { disabled: {}, deleted: {} };

export function setEntryDefs(defs) { entryDefs = defs; }
export function getEntryDefs() { return entryDefs; }

export function loadEntryState() {
  entryState = { disabled: {}, deleted: {} };
  try {
    const raw = JSON.parse(readFileSync(entryStatePath(), 'utf8'));
    if (raw && typeof raw === 'object') {
      if (raw.disabled && typeof raw.disabled === 'object') entryState.disabled = raw.disabled;
      if (raw.deleted && typeof raw.deleted === 'object') entryState.deleted = raw.deleted;
    }
  } catch {}
}
export function saveEntryState() {
  try { ensureDataDir(); writeFileSync(entryStatePath(), JSON.stringify(entryState), { mode: 0o600 }); }
  catch (e) { try { console.error('dsh-web-pass: 条目开关落盘失败(磁盘满/只读?) | %s', e?.message ?? e); } catch {} }
}

export function resolveEntries(config = {}, dshPort, clientHostTrustDefault, warn = null) {
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
  // v0.3.5：host:port 查重——patch 里误配两条指向同一后端（尤其是主 DSH 端口）会
  // 等于多开一条与管理员等价的门；同址只保留首行并告警。
  const seen = new Set();
  const out = [];
  for (const e of list) {
    const key = `${e.host}:${e.port}`;
    if (seen.has(key)) { try { warn?.(`dsh-web-pass: 跳过重复上游 ${key}（同址只保留首个条目）`); } catch {} continue; }
    seen.add(key);
    out.push(e);
  }
  return out;
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

/** 开关条目（即时落盘；停用即刻踢会话由调用方负责）。 */
export function setEntryEnabled(i, en) {
  if (en) delete entryState.disabled[i];
  else entryState.disabled[i] = true;
  saveEntryState();
}
/** 软删条目（行隐藏、其余序号不动）。 */
export function setEntryDeleted(i, del) {
  if (del) entryState.deleted[i] = true;
  else delete entryState.deleted[i];
  saveEntryState();
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

/** 运行时条目（设置页新增）追加到 patch 条目之后：追加保序，序号即会话绑定键。
 *  v0.3.5：与已有条目 host:port 重复的行直接跳过（防误配出等价管理员门）。 */
export function appendRuntimeEntries(defs, rows) {
  const out = defs.slice();
  const seen = new Set(out.map((e) => `${e.host}:${e.port}`));
  for (const r of rows ?? []) {
    if (!r || typeof r !== 'object') continue;
    const key = `${r.host}:${r.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
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

/** 测试钩子：直接装配条目表 + 开关覆盖（生产代码仅 apply() 写这两处）。 */
export function setEntriesForTest(defs, state = { disabled: {}, deleted: {} }) {
  entryDefs = defs;
  entryState = { disabled: { ...(state.disabled ?? {}) }, deleted: { ...(state.deleted ?? {}) } };
}
