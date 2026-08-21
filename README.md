# dsh-web-pass

> 简体中文 | [English](README.en.md)

一个**零依赖**的 DeepSeek Harness Web 插件：在 DSH 前面加一道**网页密码门**。

- **Cookie 会话认证**跑在反向代理上（不是 nginx Basic Auth）。密码错误次数过多（默认 3 次）→ 临时锁定（401）。
- **首次访问强制设置密码**（输入两次；强度要求 ≥8 位且含大小写字母和数字）。
- DSH 设置页新增**「网页密码」标签页**：网关状态、修改访问密码（带确认与强度指示）、一键退出登录。
- **登录访问日志**内嵌在 `/dsh-logs/`：只记录密码验证相关请求的访客 IP（成功 / 失败 / 锁定 / 浏览），自动刷新，**按大小轮转（默认单文件 1MB、保留 7 份历史）**，体积有硬上限。
- 日志不落原始 IP——用 HMAC-SHA256 假名化 + 网络前缀（IPv4 /24、IPv6 /64），可聚合分析又不泄隐私。

插件仓库里不落任何运行时数据——数据都在 `$DSH_HOME/dsh-web-pass/`（密码哈希、会话、日志）。

## 工作原理

```
浏览器 → (TLS / 反向代理) → dsh-web-pass :3081 → 127.0.0.1:3080 (DSH)
```

插件在 `dsh web` 进程内部运行一个反向代理：把 `Host`/`Origin` 改写为回环地址，从而**不改任何 DSH 配置**就能通过 DSH 的浏览器信任检查，并在其上叠加 cookie 密码认证。TLS 通常由上游终止（反向代理 / 隧道 / nginx）。

## 安装

```sh
git clone https://github.com/linz919/dsh-web-pass.git
dsh plugin --profile web add ./dsh-web-pass -w
# 然后重启 dsh web
```

确认已加载：

```sh
ss -tln | grep -E ':3081|:3082'
```

## 配置

**所有选项都有内置默认值——完全不写任何配置也能正常工作**（日志轮转默认即 1MB × 7 份）。即使 `cordis.patch.yml` 在安装其他插件时被覆盖、丢失自定义配置，功能也不受影响：日志轮转回落到内置默认，访问密码的环境变量名回落到内置的 `DSH_WEB_PASS_PASSWORD`。

来自插件配置（`cordis.patch.yml` 的 `config` 段，可选）：

| 选项 | 默认值 | 说明 |
|---|---|---|
| `port` | `3081` | 反向代理监听端口 |
| `logViewerPort` | `3082` | 内嵌日志查看器端口 |
| `maxLoginAttempts` | `3` | 锁定前允许的密码错误次数 |
| `loginLockMs` | `60000` | 超次后的锁定时长（毫秒） |
| `passwordEnv` | `DSH_WEB_PASS_PASSWORD` | 提供密码的环境变量名 |
| `trustProxy` | `false` | 是否信任 `X-Forwarded-For` / `CF-Connecting-IP` 头（用于访客 IP 识别与登录限速） |
| `logMaxBytes` | `1048576` | 访问日志单文件大小上限（字节），达到即轮转，下限 64KB |
| `logMaxFiles` | `7` | 轮转后保留的历史文件份数（`access.log.1` … `access.log.N`），超出自动删除 |

> **关于 `trustProxy`**：默认关闭时，访客 IP 与登录限速只依据 socket 直连地址，防止伪造 XFF 头污染日志或绕过限速。仅当你在网关前面部署了可信的反向代理（nginx、Cloudflare 隧道等）时才开启。

## 密码存储

- **默认为空。** 首次访问 3081 会强制进入设置页（输入两次；须 ≥8 位且含大小写字母和数字）。
- 优先级：环境变量 `DSH_WEB_PASS_PASSWORD`（设到 `dsh web` 服务进程环境里）**>** 文件 `$DSH_HOME/dsh-web-pass/password`（scrypt 哈希）。
- 如果清空（删除环境变量 / 文件）→ 下次访问重新进入设置页。
- `cordis.patch.yml` 只引用环境变量**名**——绝不要把密码明文写进去（该文件会进 git / 仓库）。

## 访问日志

- 页面入口 `/dsh-logs/`（也可从设置页「访问日志」按钮打开）：只记录 `/gate-login`、`/gate/setup`、`/gate/logout` 的请求，按「方法 + 路径 + 状态码」判定语义：
  - ✅ 验证成功（POST 登录 → 302）
  - ❌ 密码错误（POST 登录 → 200）
  - 🔒 超次锁定（POST 登录 → 401）
  - 👁 打开登录页 / 设置页（GET 浏览）
  - 🚪 登出（POST logout）
  - 🔑 首次设置完成（POST setup → 302）
- 时间使用**服务器本地时区**渲染；5 秒自动刷新；支持按 IP / 请求关键字筛选。
- 文件：`$DSH_HOME/dsh-web-pass/access.log` —— **按大小轮转**：单文件达到 `logMaxBytes`（默认 1MB）就滚动为 `access.log.1`，更早的依次后移为 `access.log.2` …，最多保留 `logMaxFiles` 份（默认 7 份），最旧的自动删除。日志总体积因此有硬上限（默认约 8MB），不会随时间无限增长。
- IP 假名化密钥存于同目录 `.hmac-key`（自动生成，0600 权限）；**不要删除它**，否则同一 IP 会产生新的假名，聚合分析断档。

## 安全说明

- 单一共享密码，无账号 / 2FA。
- **务必经 HTTPS 暴露**（上游 TLS）；不要把纯 HTTP 端口直接映射到公网。
- 登录限速与日志 IP 默认取 socket 地址；开启 `trustProxy` 后取 `X-Forwarded-For` / `CF-Connecting-IP`——用于识别参考，不是安全边界。

## 许可证

[MIT](./LICENSE)
