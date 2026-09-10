# dsh-web-pass

> [简体中文](README.md) | English

A **zero-dependency** DeepSeek Harness web plugin that puts a **web password gate** in front of DSH, with one-password-per-backend routing for guest and tool entries.

```
browser → (TLS / reverse proxy) → dsh-web-pass :3081 ┬→ 127.0.0.1:3080 (owner DSH, runs this plugin)
                                                    └→ 127.0.0.1:5101 (openclaw and other local services, optional)
```

## Feature overview

**Auth & sessions**

- **Cookie session authentication** runs on a reverse proxy (not nginx Basic Auth). Reaching the wrong-password cap (default 3) triggers a **true lockout** (401) that counts from the *last* failure; repeated lockouts escalate 2× at a time (up to 16×). Successful logins **do not clear** the failure counter.
- **Forced first-time password setup** (entered twice; must be ≥8 chars with upper- and lowercase letters and digits).
- **2-day sliding sessions** (since v0.3.2, previously fixed 24h): every authenticated request with less than 1 day of validity left renews to 2 days — daily users never get kicked, idle users re-login after 2 days.
- **Logout anywhere** (v0.3.3): non-owner entries get a "🚪 logout" chip in the page corner — one click clears the session and returns to the login page; or visit `/gate/logout` directly (GET/POST).

**Multi-password multi-upstream (guest mode, v0.3.2)**

- One password per backend: the owner password enters the main DSH, a guest password enters a clean DSH, and more passwords can front local services like openclaw or fnOS. One password box for all; errors stay generic and never reveal which entry.
- **Add upstreams from the settings page** (v0.3.3): fill "label + upstream" in the upstream table and click Add — takes effect immediately, no restart; new rows start disabled with no password; stored in `upstreams.json` (survives restarts), patch rows keep working.
- See [Multi-password multi-upstream](#multi-password-multi-upstream-guest-mode) below.

**DSH enhancements**

- **Auto-carries DSH's built-in auth** (v0.3.0): running inside the `dsh web` process, it exchanges DSH's launch token for a browser cookie and injects it — visitors just pass this gate, **no DSH token/cookie handling needed**.
- **Unlocks Host settings on non-loopback pages** (v0.3.1): when accessed via IP / domain name, the "Plugin configuration", "Models" and "General" settings pages are no longer blank (see below).

**Logs & observability**

- **Login access log** embedded at `/dsh-logs/`: password-verification requests only; size-based rotation (default 1MB × 7 files) with a hard total size cap; IPs are pseudonymized (HMAC-SHA256 + network prefix), raw IPs never stored.

**Fixed in v0.3.4**

- Proxied responses no longer carry the gate's security headers: every proxied response used to be stamped with `X-Frame-Options: DENY` and friends (meant to protect the login page), which blanked pages that backends like fnOS embed via same-origin iframes — Docker / suite apps showed "refused to connect" through the gate. These headers now apply only to the gate's own pages (login / logs); proxied responses keep the upstream's original headers, and any security headers the upstream itself sends still take effect.

**Hardened in v0.3.5**

- **Brute-force protection becomes a true lockout**: the failure counter is no longer cleared by successful logins (the old "any entry's success clears it" could be abused to brute-force other entries endlessly — verified by PoC); after reaching the cap the gate locks from the **last failure** for `loginLockMs`, escalating 2× per repeat (up to 16×) and resetting cleanly after the lock expires.
- **Injection/rewrite buffering capped at 8MB**: oversized `text/html` responses automatically degrade to streaming pass-through (injection skipped), and a client disconnect aborts the upstream immediately — prevents OOMing the gate that shares the DSH process.
- **The gate's session cookie is stripped from every forwarded request** and WebSocket handshake: `dws_session` no longer reaches any upstream (it used to be forwarded verbatim to `dsh: false` upstreams).
- **One-time token for first-time setup**: `/gate/setup` must carry the HttpOnly cookie issued by GET `/gate-setup`, so drive-by cross-site form posts cannot hijack the gate.
- **Sessions bind to the upstream identity**: a session stores both the entry index and the upstream `host:port`; both must match on every check — reordering patch rows or changing ports invalidates old sessions automatically (no more manual `sessions.jsonl` cleanup). **Upgrade note: log in again once after upgrading to v0.3.5.**
- **Re-login rotates the session**: logging in while already logged in issues a new token and revokes the old one (the old build left orphan sessions).
- Also: 2-minute upstream idle timeout, request-side aborts, a 512-connection cap, 502 pages no longer leak internal addresses, persistence errors are logged instead of swallowed, and `resolveEntries` now de-duplicates patch rows by host:port.
- **Same-release modular refactor**: `lib/` split by domain into 9 cohesive modules (proxy core 513 / index assembly+RPC 392 / entry table 146 / sessions 114 / gate pages 79 / auth carrying 81 / access log 242 / password crypto 67 / rate limiter 51 / data-dir layout 13), duplicate implementations merged; the exported API is unchanged — pure code moves with zero behavior change.

> No runtime data lives in the plugin repo — everything is under `$DSH_HOME/dsh-web-pass/` (password hashes, sessions, logs).

## How it works

The plugin runs a reverse proxy inside the `dsh web` process: it rewrites `Host`/`Origin` to the loopback address so DSH's browser trust checks pass **without any DSH configuration changes**, and layers cookie password auth on top. TLS is usually terminated upstream (reverse proxy / tunnel / nginx).

- **The gate does not forward compression negotiation** (v0.3.3): forwarded requests always strip `accept-encoding` so the upstream replies uncompressed (nginx enables gzip by default, which would skip all injections — polyfill / module rewrite / logout chip all depend on plaintext); compression is done by the reverse proxy in front of the gate.
- For `dsh: true` backends: DSH auth carrying + targeted `client-connection` module rewrite (see the two sections below).
- For `dsh: false` backends (fnOS, openclaw, etc.): pass through as-is, without DSH cookies or forced security headers.

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

Confirm it is loaded:

```sh
ss -tln | grep -E ':3081|:3082'
```

## Configuration

**Every option has a built-in default — the plugin works with no configuration at all** (log rotation defaults to 1MB × 7 files). Even if `cordis.patch.yml` gets overwritten or loses custom settings while installing other plugins, nothing breaks: log rotation falls back to the built-in defaults, and the password env var name falls back to the built-in `DSH_WEB_PASS_PASSWORD`.

From the plugin config (the `config` section in `cordis.patch.yml`, optional):

| Option | Default | Description |
|---|---|---|
| `port` | `3081` | Reverse proxy listen port |
| `logViewerPort` | `3082` | Embedded log viewer port |
| `maxLoginAttempts` | `3` | Wrong-password attempts allowed before lockout |
| `loginLockMs` | `60000` | True-lockout base duration (ms, counted from the last failure; repeated lockouts escalate 2× up to 16×) |
| `passwordEnv` | `DSH_WEB_PASS_PASSWORD` | Name of the env var providing the password |
| `trustProxy` | `false` | Trust `X-Forwarded-For` / `CF-Connecting-IP` headers (for visitor IP identification and login rate limiting) |
| `clientHostTrust` | `true` | Enable Host settings document on non-loopback pages (IP/domain access); `false` restores DSH's native behavior (settings only visible on localhost) |
| `logMaxBytes` | `1048576` | Access log per-file size cap (bytes); rotates when reached, minimum 64KB |
| `logMaxFiles` | `7` | Number of rotated history files to keep (`access.log.1` … `access.log.N`); older ones auto-deleted |
| `upstreams` | `[]` | Multi-password multi-upstream table (see below): each row has `label` / `passwordEnv` / `host` / `port` / `clientHostTrust` / `dsh` / `enabled`; omit for single-password behavior |

> **About `trustProxy`**: when off (default), visitor IPs and login rate limiting rely only on the socket address — forged forwarding headers are never adopted. When on, `X-Forwarded-For` / `CF-Connecting-IP` become the **rate-limit key**, so enable it only behind a trusted reverse proxy that **overwrites** those headers (nginx with `proxy_set_header X-Forwarded-For $remote_addr;`, Cloudflare tunnel, etc.); a merely pass-through proxy would hand attackers an unlimited set of rate-limit keys.

### Password storage

- **Empty by default.** First visit to 3081 forces the setup page (entered twice; must be ≥8 chars with upper- and lowercase letters and digits).
- Priority (per entry): environment variable (e.g. `DSH_WEB_PASS_PASSWORD`, set in the `dsh web` service environment) **>** file `$DSH_HOME/dsh-web-pass/password` (admin entry) or `password.<i>` (entry i, scrypt hash).
- If cleared (env var / file deleted) → next visit re-enters the setup page.
- `cordis.patch.yml` only references the env var **name** — never write plaintext passwords into it (the file goes into git / the repo).
- Changing a password on the settings page never asks for the old one; on save the old password is invalidated immediately and all its sessions are revoked (2-day sliding sessions included). Owner forgot the password: delete the file (deleting `sessions.jsonl` in the same directory too is cleaner) to return to the forced setup page; for env-var passwords, `unset` and restart.

## Multi-password multi-upstream (guest mode)

### Adding, enabling and disabling

- **One row = one password + one backend**: preferred way — fill **label + upstream (host:port)** in the settings-page upstream table and click "Add" (takes effect immediately, no restart; new rows **start disabled with no password**); or add a row to `upstreams` in `cordis.patch.yml` and **restart** `dsh web`. Rows added from the page persist in `$DSH_HOME/dsh-web-pass/upstreams.json` (0600, survives restart), coexist with patch rows and are appended after them; password values can be changed live on the settings "Web password" tab without a restart.
- Disabling a row kicks its sessions instantly (no restart); deleting a row invalidates it immediately (soft delete: row hidden, index unchanged); deleting the patch row and restarting removes it completely; the admin entry cannot be disabled or deleted.

### Password rules

- **Guest passwords are set by the owner only**: there is no registration page. Use the row's "reset password" button in the settings upstream table, or the unified reset box below (selecting a table row auto-selects the entry).
- **Passwords must differ across entries**: setting a password that duplicates another entry's env-var plaintext is rejected.

### Login behavior

- **One login box for all**: wrong passwords always report "wrong password, please retry" without revealing which entry; rate limiting is global per source IP (successful logins do not clear it). If a backend is down, that entry's login reports "this entrance is currently unavailable" while the owner is unaffected.
- **Multiple identities in one browser**: cookies are shared per browser (not per tab), so one browser holds at most one entry's login at a time; to use several identities side by side (e.g. DSH and fnOS), open separate **private/incognito windows** and log into the respective entries (their cookies are independent) — no need to log out of each other.

### Isolation and management

- **Guests never see the owner**: run a clean DSH for guests (new port + new data dir, without this plugin) so its records are naturally empty; keep guest entries at `clientHostTrust: false` (default) so guest settings pages stay blank and the model cannot be changed. The gate only forwards — it does not run backends; backends run themselves and bind `127.0.0.1` only.
- **Only DSH backends get auth carrying / rewriting**: entries with `dsh: true` each hold their own DSH cookie and get the module rewrite; for reverse-proxying non-DSH services like openclaw or fnOS keep `dsh: false` (default) for pass-through, avoiding leaking DSH cookies to them.
- **The admin surface lives only in the owner's DSH**: the settings page (including the upstream table and the `/dsh-logs/` entry) exists only in the main DSH that runs this plugin; guest clean DSH instances don't have it, so guests cannot touch it.
- **Logs carry the entry**: each access-log line ends with the entry name (older lines show `-`), filterable by entry.

### Entry index and session binding (upgrade notes)

- **Entry index + upstream address = session binding key** (v0.3.5): a session records both the entry index and that entry's upstream `host:port` at issue time; both must match on every check — reordering patch rows or changing ports and restarting invalidates old sessions automatically (just log in again; no manual `sessions.jsonl` cleanup needed). Order remains "admin → patch rows → page-added rows", append-only with stable soft-deleted indexes.
- **Upgrade note**: both DSH instances share one copy of the program — upgrade once; restart the owner's first and verify owner login + settings page, then restart the guest's and verify it stays clean.

## DSH built-in auth carrying

DSH Web ships with a browser-auth layer (process launch-token exchanged for a 30-day cookie). This plugin runs inside the `dsh web` process and can obtain a process-token URL via `ctx.connection.authenticatedUrl()`, internally exchange it for DSH's persistent cookie, and **inject it into every forwarded request and WebSocket handshake** — visitors behind the password gate never see DSH's "authentication required".

- Automatic: warm-up on start + silent refresh every 6 hours; self-heals after DSH restarts (the next request re-fetches on failure).
- Secure: the launch-token never travels through any plugin forwarding path and never reaches any upstream or the browser; only the password gate is exposed externally. (Note: the DSH platform itself prints a token-bearing start URL to the service's stdout — that is DSH behavior, not this plugin's; protect service logs per your DSH ops practice.)
- Visible status: the settings "Web password" tab shows a `dshAuthHolding` field (whether the DSH cookie is being carried).
- Zero configuration: enabled automatically whenever `dsh web` provides `ctx.connection`; falls back to the old behavior otherwise (visitors still need a DSH token).

## Unlock Host settings on non-loopback pages

DSH's client only mounts the host settings document when the page URL is `localhost`/`127.x`; via LAN IP or domain (including through this gate) settings degrade to memory mode — the **"Plugin configuration", "Models" and "General" tabs go completely blank** (pure-RPC features like the plugin list and chat are unaffected).

The plugin performs one targeted rewrite of DSH's `client-connection` module at the proxy layer, forcing that check to true: the settings page works fully on 3081 (LAN IP / public domain). The browser URL is unchanged and the password gate remains the only entrance.

- On by default; set `clientHostTrust: false` to restore DSH's native behavior.
- The rewritten module is served with `cache-control: no-cache`. **After upgrading, hard-refresh once per device (Ctrl+F5)** — the old module was cached `immutable` for a year and a normal refresh won't re-fetch; after one hard refresh it stays current automatically.
- If a future DSH version changes that check (rewrite misses), the log reports "isLoopback anchor not found"; the settings page goes blank again while everything else keeps working — sync the anchor with the plugin update.

## Access log

- Page at `/dsh-logs/` (also reachable via the settings page "Access log" button): only requests to `/gate-login`, `/gate/setup`, `/gate/logout` are recorded, with semantics derived from "method + path + status":
  - ✅ verified (POST login → 302)
  - ❌ wrong password (POST login → 200)
  - 🔒 locked out (POST login → 401)
  - 👁 login / setup page opened (GET browse)
  - 🚪 logout (POST logout)
  - 🔑 first-time setup completed (POST setup → 302)
- Times render in the **server's local timezone**; auto-refresh every 5s; filter by IP / request keyword.
- File: `$DSH_HOME/dsh-web-pass/access.log` — **size-based rotation**: when a file reaches `logMaxBytes` (default 1MB) it rolls to `access.log.1`, older ones shift to `access.log.2` …, keeping at most `logMaxFiles` (default 7) with the oldest auto-deleted. Total log size is therefore hard-capped (≈8MB by default) and never grows unbounded.
- The IP pseudonymization key lives in `.hmac-key` in the same directory (auto-generated, 0600); **do not delete it**, otherwise the same IP gets new pseudonyms and aggregate analysis breaks.

## Security notes

- One password per backend (multi-password multi-upstream), no accounts / 2FA.
- **Always expose via HTTPS** (upstream TLS); never port-map a plain HTTP port straight to the internet.
- The gate's own pages (login / logs) carry `X-Frame-Options: DENY` and other security headers; proxied responses get no extra security headers (since v0.3.4), and whatever the upstream itself sends passes through as-is.
- Login rate limiting and log IPs use the socket address by default (forged forwarding headers are ignored); with `trustProxy` they switch to `X-Forwarded-For` / `CF-Connecting-IP` as the **rate-limit key** — enable only behind a trusted proxy that overwrites those headers, otherwise it hands attackers an unlimited set of rate-limit keys.

## Version history

| Version | Highlights |
|---|---|
| v0.3.5 | Hardening: true lockout with exponential backoff (success no longer clears the counter); 8MB injection buffer cap + disconnect aborts; gate session cookie stripped from forwarding; one-time setup token; sessions bound to upstream identity (re-login once after upgrade); re-login rotates sessions; upstream timeouts / request aborts / persistence error logs. **Same release includes a modular refactor**: `lib/` split by domain into 9 cohesive modules (largest 513 lines, index.js 684→392), pure code moves with zero behavior change |
| v0.3.4 | Fixed: proxied responses no longer carry the gate's security headers (XFO DENY blanked fnOS same-origin iframe suite apps through the gate) |
| v0.3.3 | Add upstreams from the settings page (instant); logout chip; strip `accept-encoding` to keep injections working |
| v0.3.2 | Multi-password multi-upstream (guest mode); 2-day sliding sessions; per-entry log column |
| v0.3.1 | Unlock Host settings on non-loopback pages |
| v0.3.0 | DSH built-in auth carrying |

## License

[MIT](./LICENSE)
