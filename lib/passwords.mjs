// dsh-web-pass 密码学核心（v0.3.5 从 index.js 抽离）：scrypt 哈希 + 恒时校验 + 强度规则。
// 自描述的 modular-crypt 风格哈希串（参数内嵌，将来可平滑调强）；
// 环境变量场景兼容明文：timingSafeEqual 不允许长度不等，必须先比长度（仅泄漏长度）。
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { readFileSync, writeFileSync } from 'node:fs';
import { passwordPath, ensureDataDir } from './paths.mjs';

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

export async function hashPassword(password) {
  const salt = randomBytes(16).toString('base64');
  const key = await deriveScrypt(password, salt, SCRYPT_KEYLEN, 2 ** SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P);
  return [HASH_TAG, 2 ** SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, salt, key.toString('base64')].join(':');
}

export async function verifyPassword(password, stored) {
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
export function passwordStrength(p) {
  if (typeof p !== 'string' || p.length < 8) return { ok: false, reason: '密码至少需要 8 位' };
  if (!/[a-z]/.test(p)) return { ok: false, reason: '密码必须包含小写字母' };
  if (!/[A-Z]/.test(p)) return { ok: false, reason: '密码必须包含大写字母' };
  if (!/[0-9]/.test(p)) return { ok: false, reason: '密码必须包含数字' };
  return { ok: true, reason: null };
}

// ---- 密码文件读写（scrypt 哈希串；0600；writePasswordHash 失败会抛出——调用方负责提示）----
export function readPasswordHash(entry = 0) {
  try { const p = readFileSync(passwordPath(entry), 'utf8').trim(); if (p) return p; } catch {}
  return null;
}
export function writePasswordHash(entry, h) {
  ensureDataDir();
  writeFileSync(passwordPath(entry), h, { mode: 0o600 });
}
