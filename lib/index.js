// dsh-web-pass 插件入口：启动局域网代理(3081) + 注册改密码 RPC + 移动端布局(由代理注入 HTML)
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir, networkInterfaces } from 'node:os';
import { createGateProxy, DEFAULT_INJECT } from './proxy.mjs';
import { installGateRpc, GATE_RPC_CHANNEL, GATE_ENDPOINTS } from './web-rpc.js';
import { createAccessLogger, createLogViewer } from './accesslog.mjs';

const name = 'dsh-web-pass';
const inject = ['connection', 'webServer'];

// ---- 密码存储：默认空。优先级：环境变量 > 文件 $DSH_HOME/dsh-web-pass/password ----
// 环境变量名由 config.passwordEnv 指定（cordis.patch.yml 只写变量名，不写值）。没设密码时
// 代理会强制先设置密码（首次访问 3081 →「首次设置密码」页）。
function dshHome() { return process.env.DSH_HOME ?? join(homedir(), '.dsh'); }
function dataDir() { return join(dshHome(), 'dsh-web-pass'); }
function passwordPath() { return join(dataDir(), 'password'); }

let memPassword = null;      // 设置页改过后的内存缓存
let passwordEnvName = null;  // apply() 里由 config.passwordEnv 设定

function readPasswordFile() {
  try { const p = readFileSync(passwordPath(), 'utf8').trim(); if (p) return p; } catch {}
  return null;
}
function writePasswordFile(p) {
  mkdirSync(dirname(passwordPath()), { recursive: true });
  writeFileSync(passwordPath(), p, { mode: 0o600 });
}
function getPassword() {
  if (passwordEnvName) {
    const e = String(process.env[passwordEnvName] ?? '').trim();
    if (e) return e;
  }
  if (memPassword) return memPassword;
  return readPasswordFile(); // null → 未设置 → 强制设置密码
}
function setPassword(p) { memPassword = p; writePasswordFile(p); }

// ---- 选局域网 IP（手机同 WiFi 可达）----
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
  // 任何异常都不允许冒泡到 dsh web（否则看门狗会反复重启主进程）
  try {
    const logger = ctx.logger?.(name) ?? console;
    const dshPort = internals.dshPort ?? ctx.webServer?.port;
    if (!dshPort) { logger.warn('dsh-web-pass: 拿不到 dsh web 端口，跳过'); return () => {}; }

    const port = internals.port ?? config.port ?? 3081;
    passwordEnvName = (typeof config.passwordEnv === 'string' && config.passwordEnv) ? config.passwordEnv : 'DSH_WEB_PASS_PASSWORD';
    const auth = { getToken: () => getPassword(), isProtected: () => true };

    // 访问日志：由网关自己记录访客 IP（真实 IP 按 XFF 记到），
    // 文件 $DSH_HOME/dsh-web-pass/access.log（按天轮转、保留 30 天）；内嵌查看器监听
    // 127.0.0.1:<logViewerPort>，/dsh-logs/ 指向它。
    const logPort = internals.logViewerPort ?? config.logViewerPort ?? 3082;
    const accessFile = join(dataDir(), 'access.log');
    const accessLogger = createAccessLogger({ file: accessFile });

    let proxy = null;
    let logViewer = null;
    const disposers = [];

    const getStatus = async () => {
      const lan = selectLanIPv4();
      const proxyPort = proxy?.port ?? null;
      const lanUrl = lan && proxyPort ? `http://${lan}:${proxyPort}` : null;
      // 零依赖：不生成二维码，仅返回局域网地址（手机可直接输入/扫码软件扫地址）
      return { proxyRunning: proxy !== null, proxyPort, lanUrl, lanQr: null, dshPort, logViewerPort: logViewer?.port ?? null };
    };

    try { disposers.push(installGateRpc(ctx, { getPassword, setPassword, getStatus, log: logger })); }
    catch (e) { logger.error('dsh-web-pass: RPC 注册失败(已忽略) | %s', e?.message ?? e); }

    void createLogViewer({ file: accessFile, port: logPort }).then((v) => {
      logViewer = v;
      logger.info('dsh-web-pass: 日志查看器已就绪 :%d | log viewer ready', v.port);
    }).catch((err) => {
      logger.error('dsh-web-pass: 日志查看器启动失败(已忽略) | %s', err?.message ?? err);
    });

    void createGateProxy({
      port, host: '0.0.0.0', upstream: { host: '127.0.0.1', port: dshPort },
      injectHtml: DEFAULT_INJECT, auth, onSetPassword: setPassword,
      // 只记密码验证请求（/gate-login）的 IP —— 量很小，且正是想监控的「谁在尝试访问密码」。
      // 状态码即可区分：302=成功、200=密码错误、401=超次锁定。
      onAccess: (req, res) => {
        // 记录密码验证（/gate-login）与首次设置（/gate/setup）请求的 IP。
        // 状态码即可区分：302=成功、200=密码错误/未通过校验、401=超次锁定。
        if (req.url === '/gate-login' || req.url === '/gate/setup') accessLogger.log(req, res).catch(() => {});
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

export { name, inject, GATE_RPC_CHANNEL, GATE_ENDPOINTS };
