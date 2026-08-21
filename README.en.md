# dsh-web-pass

> [简体中文](README.md) | English

A **zero-dependency** DeepSeek Harness web plugin that puts a **web password gate** in front of DSH.

- **Cookie session authentication** runs on a reverse proxy (not nginx Basic Auth). Too many wrong-password attempts (default 3) → temporary lockout (401).
- **Forced first-time password setup** (entered twice; must be ≥8 chars with upper- and lowercase letters and digits).
- Adds a **"Web password" tab** to the DSH settings page: gateway status, change the access password (with confirmation and a strength meter), one-click logout.
- **Login access log** embedded at `/dsh-logs/`: records visitor IPs only for password-verification requests (success / failure / lockout / browsing), auto-refresh, **size-based rotation (1MB per file, 7 history files by default)** with a hard total size cap.
- Raw IPs are never written to the log — HMAC-SHA256 pseudonymization + network prefix (IPv4 /24, IPv6 /64) keeps it aggregatable without leaking privacy.

No runtime data lives in the plugin repo — everything goes to `$DSH_HOME/dsh-web-pass/` (password hash, sessions, logs).

## How it works

```
Browser → (TLS / reverse proxy) → dsh-web-pass :3081 → 127.0.0.1:3080 (DSH)
```

The plugin runs a reverse proxy inside the `dsh web` process: it rewrites `Host`/`Origin` to the loopback address so it passes DSH's browser trust check **without changing any DSH configuration**, and layers cookie password authentication on top. TLS is usually terminated upstream (reverse proxy / tunnel / nginx).

## Install

**Option 1: from npm (recommended)**

```sh
dsh plugin --profile web add dsh-web-pass
# then restart dsh web
```

**Option 2: from source**

```sh
git clone https://github.com/linz919/dsh-web-pass.git
dsh plugin --profile web add ./dsh-web-pass -w
# then restart dsh web
```

Verify it is loaded:

```sh
ss -tln | grep -E ':3081|:3082'
```

## Configuration

**Every option has a built-in default — the plugin works with no configuration at all** (log rotation defaults to 1MB × 7 files). Even if `cordis.patch.yml` gets overwritten while installing other plugins and loses your custom settings, nothing breaks: log rotation falls back to the built-in defaults, and the password environment variable name falls back to the built-in `DSH_WEB_PASS_PASSWORD`.

From plugin config (the `config` section of `cordis.patch.yml`, optional):

| Option | Default | Description |
|---|---|---|
| `port` | `3081` | Reverse proxy listen port |
| `logViewerPort` | `3082` | Embedded log viewer port |
| `maxLoginAttempts` | `3` | Allowed wrong-password attempts before lockout |
| `loginLockMs` | `60000` | Lockout duration in milliseconds |
| `passwordEnv` | `DSH_WEB_PASS_PASSWORD` | Name of the env var providing the password |
| `trustProxy` | `false` | Trust `X-Forwarded-For` / `CF-Connecting-IP` headers (for visitor IP identification and login rate limiting) |
| `logMaxBytes` | `1048576` | Max size of one access-log file in bytes; rotation triggers when reached, floor 64KB |
| `logMaxFiles` | `7` | Number of rotated history files kept (`access.log.1` … `access.log.N`); older ones are deleted automatically |

> **About `trustProxy`**: when off (the default), visitor IP and login rate limiting use only the direct socket address, preventing forged XFF headers from polluting logs or bypassing rate limits. Enable it only when a trusted reverse proxy (nginx, Cloudflare tunnel, etc.) sits in front of the gateway.

## Password storage

- **Empty by default.** The first visit to port 3081 forces the setup page (enter twice; ≥8 chars including upper- and lowercase letters and digits).
- Priority: env var `DSH_WEB_PASS_PASSWORD` (set in the `dsh web` service environment) **>** file `$DSH_HOME/dsh-web-pass/password` (scrypt hash).
- If cleared (env var / file removed) → the next visit shows the setup page again.
- `cordis.patch.yml` only references the env var **name** — never put a plaintext password in it (that file goes into git / the repo).

## Access log

- Page entry `/dsh-logs/` (also reachable from the "Access log" button on the settings page): only requests to `/gate-login`, `/gate/setup`, `/gate/logout` are recorded; semantics are derived from method + path + status code:
  - ✅ Login success (POST login → 302)
  - ❌ Wrong password (POST login → 200)
  - 🔒 Lockout (POST login → 401)
  - 👁 Login/setup page viewed (GET browse)
  - 🚪 Logout (POST logout)
  - 🔑 First-time setup completed (POST setup → 302)
- Times are rendered in the **server's local timezone**; auto-refresh every 5 seconds; filter by IP / request keyword.
- File: `$DSH_HOME/dsh-web-pass/access.log` — **rotated by size**: when the file reaches `logMaxBytes` (default 1MB) it rolls over to `access.log.1`, older ones shift to `access.log.2` …, keeping at most `logMaxFiles` files (default 7); the oldest is deleted automatically. Total log size is therefore hard-capped (~8MB by default) and never grows unbounded.
- The IP pseudonymization key is stored in `.hmac-key` in the same directory (auto-generated, mode 0600); **do not delete it**, or the same IP will produce new pseudonyms and aggregation analysis breaks.

## Security notes

- Single shared password; no accounts / 2FA.
- **Always expose over HTTPS** (upstream TLS); never map the plain HTTP port directly to the public internet.
- Login rate limiting and logged IPs use the socket address by default; with `trustProxy` enabled they use `X-Forwarded-For` / `CF-Connecting-IP` — for identification reference, not a security boundary.

## License

[MIT](./LICENSE)
