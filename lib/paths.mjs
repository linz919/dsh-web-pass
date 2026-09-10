// dsh-web-pass 数据目录布局（v0.3.5 从 index.js 抽离）。
// 全部运行时数据落 $DSH_HOME/dsh-web-pass/，0600；多条目：条目 0 沿用老 `password` 文件，其它 `password.<i>`。
import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';

export function dshHome() { return process.env.DSH_HOME ?? join(homedir(), '.dsh'); }
export function dataDir() { return join(dshHome(), 'dsh-web-pass'); }
export function passwordPath(entry = 0) { return entry === 0 ? join(dataDir(), 'password') : join(dataDir(), `password.${entry}`); }
export function sessionsPath() { return join(dataDir(), 'sessions.jsonl'); }
export function entryStatePath() { return join(dataDir(), 'entries.json'); }
export function runtimeUpstreamsPath() { return join(dataDir(), 'upstreams.json'); }
export function ensureDataDir() { try { mkdirSync(dataDir(), { recursive: true }); } catch {} }
