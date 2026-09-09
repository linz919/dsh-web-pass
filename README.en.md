# dsh-web-pass

> [简体中文](README.md) | English

A **zero-dependency** DeepSeek Harness web plugin that puts a **web password gate** in front of DSH.

- **Cookie session authentication** runs on a reverse proxy (not nginx Basic Auth). Too many wrong-password attempts (default 3) → temporary lockout (401).
- **Multi-password multi-upstream** (new in v0.3.2): one password per backend — the owner password enters the main DSH, a guest password enters a clean DSH, and more passwords can front local services like openclaw. The login page stays a single password box; the gateway matches the password and routes accordingly; errors stay generic and never reveal which entry.
- **Add upstreams from the settings page** (new in v0.3.3): fill "label + upstream" in the upstream table and click Add — new entries start disabled with no password; they persist in the data dir (`upstreams.json`) across restarts, and patch rows keep working as before.
- **2-day sliding sessions** (since v0.3.2, previously fixed 24h): every authenticated request with less than 1 day of validity left renews to 2 days — daily users never get kicked, idle users re-login after 2 days.
- **Auto-carries DSH's built-in auth**: running inside the `dsh web` process, it exchanges DSH's launch token for a browser cookie and injects it — visitors just pass this gate, **no DSH token/cookie handling needed**.
- **Unlocks Host settings on non-loopback pages** (new in v0.3.1): when accessed via IP / domain name, the "Plugin configuration", "Models" and "General" settings pages are no longer blank (see below).
- **Forced first-time password setup** (entered twice; must be ≥8 chars with upper- and lowercase letters and digits).
- Adds a **"Web password" tab** to the DSH settings page: gateway status, change the access password (with confirmation and a strength meter), one-click logout.
- **Login access log** embedded at `/dsh-logs/`: records visitor IPs only for password-verification requests (success / failure / lockout / browsing), auto-refresh, **size-based rotation (1MB per file, 7 history files by default)** with a hard total size cap.
- Raw IPs are never written to the log — HMAC-SHA256 pseudonymization + network prefix (IPv4 /24, IPv6 /64) keeps it aggregatable without leaking privacy.

No runtime data lives in the plugin repo — everything goes to `$DSH_HOME/dsh-web-pass/` (password hash, sessions, logs).

## DSH built-in auth carrying (new in v0.3.0)

DSH Web has its own browser-auth layer (a per-process launch token that mints a 30-day cookie). Since this plugin lives inside the `dsh web` process, it can obtain the process-token URL via `ctx.connection.authenticatedUrl()`, exchange it internally for DSH's persistent cookie, and **inject that cookie into every forwarded request and WebSocket handshake** — so visitors coming through the gate never see DSH's "authentication required".

- Automatic: pre-warmed at startup, silently refreshed every 6 hours, self-healing after a DSH restart (the next request re-acquires on failure).
- Safe: the launch token never leaves the process or the wire; externally only the password gate is exposed.
- Observable: the settings "Web password" tab exposes a `dshAuthHolding` field (whether the DSH cookie is currently held).
- No configuration needed: enabled automatically whenever `dsh web` provides `ctx.connection`; falls back to the old behavior (visitors need the DSH token) when unavailable.

## Unlock Host settings on non-loopback pages (new in v0.3.1)

The DSH client only mounts the host settings document when the page address is `localhost`/`127.x`; accessed via a LAN IP or a domain name (including through this gate), settings degrade to in-memory mode — **the "Plugin configuration", "Models" and "General" tabs render blank** (pure-RPC features like the plugin list and chat are unaffected).

This plugin performs one targeted rewrite of the `client-connection` module served by DSH, making that check always true: the settings pages work fully on :3081 (LAN IP / public domain). The browser URL is unchanged and the password gate remains the only entry point.

- On by default; set `clientHostTrust: false` in the config to restore DSH's native behavior.
- The rewritten module is served with `cache-control: no-cache`. **After upgrading from an older version, hard-refresh once per device (Ctrl+F5)** — the old module was cached as `immutable` for a year, so a normal reload never reaches the server; after that one hard refresh everything stays current automatically.
- If a future DSH version changes the check (the rewrite no longer matches), the log warns "isLoopback anchor not found"; settings go back to blank while everything else keeps working — update the anchor together with the plugin.

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
| `clientHostTrust` | `true` | Mount the host settings document on non-loopback pages (IP/domain access); `false` restores DSH's native behavior (settings only visible from localhost) |
| `logMaxBytes` | `1048576` | Max size of one access-log file in bytes; rotation triggers when reached, floor 64KB |
| `logMaxFiles` | `7` | Number of rotated history files kept (`access.log.1` … `access.log.N`); older ones are deleted automatically |
| `upstreams` | `[]` | Multi-password multi-upstream table (see "Multi-password multi-upstream" below): each entry has `label` / `passwordEnv` / `host` / `port` / `clientHostTrust` / `dsh` / `enabled`; empty means the v0.3.x single-password behavior |

> **About `trustProxy`**: when off (the default), visitor IP and login rate limiting use only the direct socket address, preventing forged XFF headers from polluting logs or bypassing rate limits. Enable it only when a trusted reverse proxy (nginx, Cloudflare tunnel, etc.) sits in front of the gateway.

## Multi-password multi-upstream (new in v0.3.2: guest mode)

```
Browser → dsh-web-pass :3081 → by password → 127.0.0.1:3080 (owner's main DSH)
                                          → 127.0.0.1:3085 (guest's clean DSH)
                                          → 127.0.0.1:5101 (openclaw or another local service)
```

- **One row = one password + one backend**: preferred way (new in v0.3.3): fill **label + upstream (host:port)** in the settings-page upstream table and click "Add" — takes effect immediately, no restart; new rows **start disabled with no password**. You can still add a row to `upstreams` in `cordis.patch.yml` and **restart** `dsh web`. Rows added from the page persist in `$DSH_HOME/dsh-web-pass/upstreams.json` (0600, survives restart), appended after patch rows; password values can be changed live on the settings "Web password" tab without a restart.
- **Only the owner sets the guest password**: no registration page. Use the upstream table's "Reset password" or the unified box below it (pick the entry first — clicking a row pre-selects it). Saving voids that entry's old password immediately and revokes all its sessions; no current password is required (the login session itself is the credential).
- **Entries must have distinct passwords**: saving is rejected when the new password equals another entry's env-var plaintext.
- **One login box**: a wrong password always answers "wrong password, try again", never revealing which entry; rate limiting shares one counter across entries. When an entry's backend is down, that entry's login says "entry not enabled yet" while the owner keeps working.
- **Guests never see the owner**: point the guest entry at a clean DSH (new port + new data dir, without this plugin) for natural empty history; keep that entry's `clientHostTrust` at `false` (the default) so the guest settings stay blank and models can't be changed. The gate only routes — backends are your own job, bound to `127.0.0.1`.
- **DSH carrying/rewriting is per entry**: entries with `dsh: true` each hold their own DSH cookie and may rewrite the module; point openclaw and other non-DSH services at `dsh: false` (the default) for plain passthrough, so no DSH cookie leaks to them.
- **Management lives only in the owner's room**: the settings tab (upstream table, log entry `/dsh-logs/`) exists only on the main DSH carrying this plugin; the guest's clean room has no such tab, so guests can't touch management. Disabling an entry kicks its sessions immediately (no restart); deleting takes effect immediately (soft delete: row hidden, indexes unchanged), and removing the row from the patch + restart makes it permanent; the admin entry can't be disabled or deleted.
- **Entry index = session binding key**: sessions bind to an entry's position in the table, ordered "admin → patch rows → page-added rows". Append-only + soft delete keeps indexes stable; if you manually reorder `upstreams` in the patch, clear `sessions.jsonl` in the same directory before restarting, otherwise old sessions (≤2 days) may map to a different backend.
- **Log out from anywhere** (v0.3.3): guest/tool rooms have no settings tab — their pages automatically get a floating "🚪 退出" chip at the bottom-right (small, semi-transparent), clicking it clears the session and returns to the login page; `/gate/logout` also works directly (GET or POST). The owner's settings tab keeps its own logout button.
- **The gate strips `accept-encoding`** (v0.3.3): forwarded requests never negotiate compression, so upstreams answer uncompressed (nginx defaults to gzip, which would skip every injection — polyfill, module rewrite, logout chip); compression is the job of any reverse proxy in front of the gate.
- **Multiple identities in one browser**: cookies are shared browser-wide (tabs included), so one browser holds a single entry login at a time; to use several identities side by side (e.g. DSH and fnOS together), open separate **incognito windows** and log into each entry there (incognito cookies are isolated) — no need to log each other out.
- **Logs carry the entry**: each access-log line ends with the entry label (pre-v0.3.2 lines have no such column and show `-`), filterable by entry.
- **Upgrading**: both DSH instances share one binary — upgrade once; restart the main one first and verify the owner login + settings, then restart the guest one and verify it is clean.

## Password storage

- **Empty by default.** The first visit to port 3081 forces the setup page (enter twice; ≥8 chars including upper- and lowercase letters and digits).
- Priority (per entry): env var (e.g. `DSH_WEB_PASS_PASSWORD`, set in the `dsh web` service environment) **>** file `$DSH_HOME/dsh-web-pass/password` (admin entry) or `password.<i>` (entry i, scrypt hash).
- If cleared (env var / file removed) → the next visit shows the setup page again.
- `cordis.patch.yml` only references the env var **name** — never put a plaintext password in it (that file goes into git / the repo).
- Changing a password needs no current password; saving voids that entry's old password immediately and revokes all its sessions (2-day sliding sessions included). Owner forgot the password: delete the file (delete `sessions.jsonl` alongside for a cleaner cut) to return to the forced setup page; when an env var is used, `unset` it first and restart.

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
- Each line ends with the entry label (e.g. the guest entry logs its label; pre-v0.3.2 lines have no such column and show `-`), filterable by entry.
- The IP pseudonymization key is stored in `.hmac-key` in the same directory (auto-generated, mode 0600); **do not delete it**, or the same IP will produce new pseudonyms and aggregation analysis breaks.

## Security notes

- One password per backend (multi-password multi-upstream); no per-user accounts / 2FA.
- **Always expose over HTTPS** (upstream TLS); never map the plain HTTP port directly to the public internet.
- Login rate limiting and logged IPs use the socket address by default; with `trustProxy` enabled they use `X-Forwarded-For` / `CF-Connecting-IP` — for identification reference, not a security boundary.

## License

[MIT](./LICENSE)
