# dsh-web-pass

A **zero-dependency** DeepSeek Harness Web plugin that puts a **web-password gate** in front of DSH.

- **Cookie-password auth** on a reverse proxy (not nginx Basic Auth). Too many wrong tries (default 3) → temporary lock (401).
- **First visit forces password setup** (entered twice; pure-numeric passwords rejected).
- **「网页密码 / Web password settings」tab** in the DSH Settings page: gateway status, change the access password (with confirm), and a **one-click random strong password**.
- **Login access log** at `/dsh-logs/`: records only the visitor IP of password-verification requests (success / failed / locked), auto-refreshes, **kept 30 days with daily rotation**.

No runtime data lives in the plugin/ repo — it's under `$DSH_HOME/dsh-web-pass/` (password + logs).

## How it works

```
browser → (TLS / 反向代理) → dsh-web-pass :3081 → 127.0.0.1:3080 (DSH)
```

The plugin runs a reverse proxy inside the `dsh web` process. It rewrites `Host`/`Origin` to loopback so DSH's browser trust gate is satisfied **without changing any DSH config**, and adds cookie-password auth on top. TLS is normally terminated upstream (reverse proxy / tunnel / nginx).

## Install

```sh
git clone https://github.com/<you>/dsh-web-pass.git
dsh plugin --profile web add ./dsh-web-pass -w
# then restart dsh web
```

Confirm it loaded:

```sh
ss -tln | grep -E ':3081|:3082'
```

## Configuration

Values come from plugin config (`lib/index.js` / `cordis.patch.yml`):

| option | default | meaning |
|---|---|---|
| `port` | `3081` | reverse-proxy listen port |
| `logViewerPort` | `3082` | embedded access-log viewer port |
| `maxLoginAttempts` | `3` | wrong-password count before locking |
| `loginLockMs` | `60000` | lockout duration after exceeding attempts |
| `passwordEnv` | `DSH_WEB_PASS_PASSWORD` | env var name that may supply the password |

## Password storage

- **Default: empty.** First visit to 3081 forces a password-setup page (enter twice; pure-numeric rejected).
- Priority: environment variable `DSH_WEB_PASS_PASSWORD` (set it in the `dsh web` service env) **>** file `$DSH_HOME/dsh-web-pass/password`.
- If it's cleared (env removed / file deleted) → the setup page is required again.
- `cordis.patch.yml` only references the env var **name** — never put the secret value there (it ends up in git / the repo).

## Access log

- `/dsh-logs/`: only `/gate-login` and `/gate/setup` requests' visitor IP; shows 成功/失败/已锁定; 5-second auto-refresh.
- File: `$DSH_HOME/dsh-web-pass/access.log` — **daily rotation, 30 days kept** (`access.log.YYYY-MM-DD`; older files auto-deleted).

## Security notes

- Single shared password, no accounts / 2FA.
- Expose **only over HTTPS** (upstream TLS); don't map the plain-HTTP port directly to the public internet.
- Login rate-limit and logged IP derive from `X-Forwarded-For` / `CF-Connecting-IP`; for identification, not a boundary.

## License

[MIT](./LICENSE)
