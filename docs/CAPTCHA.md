# 注册与登录验证码逻辑（Turnstile）

## 适用范围
- `/api/auth/register` 与 `/api/auth/login` 会在进入用户名/密码校验前进行验证码校验（Cloudflare Turnstile）。【F:handlers/auth.go†L31-L173】
- 验证函数位于 `utils.VerifyTurnstileToken`，根据配置决定是否启用验证码。【F:utils/turnstile.go†L1-L131】

## 注册与登录的验证码流程
1. 前端提交 `turnstile_token` 字段（Turnstile 响应 token）。【F:handlers/auth.go†L17-L30】
2. 后端从请求中读取客户端 IP（`c.ClientIP()`），用于 Turnstile 的 `remoteip` 字段。【F:handlers/auth.go†L49-L55】【F:handlers/auth.go†L330-L338】
3. 后端调用 `VerifyTurnstileToken(token, remoteIP, expectedAction)`：
   - 当 `TURNSTILE_ENABLED=false` 时直接跳过校验，返回成功。【F:utils/turnstile.go†L38-L46】
   - 当 `TURNSTILE_ENABLED=true` 且缺少 `TURNSTILE_SECRET_KEY` 时视为服务端配置错误（500）。【F:utils/turnstile.go†L48-L53】
   - 当 token 为空时视为客户端错误（400）。【F:utils/turnstile.go†L55-L58】
   - 调用 Turnstile API (`/siteverify`) 并解析结果：
     - `success=false` 视为验证码失败（400）。【F:utils/turnstile.go†L76-L111】
     - 如果配置了 `TURNSTILE_ALLOWED_HOSTNAME`，会校验 Turnstile 回传的 `hostname`（大小写不敏感）。【F:utils/turnstile.go†L113-L124】
     - `expectedAction` 目前传入空字符串，因此不会强制校验 `action` 字段；代码注释建议前端设置 `data-action="register"`/`"login"` 以便未来启用 action 校验。【F:handlers/auth.go†L51-L55】【F:handlers/auth.go†L143-L147】【F:utils/turnstile.go†L104-L111】
4. 若 Turnstile 校验失败：
   - 服务端错误（无法请求/解析 Turnstile）返回 500：`Failed to verify captcha`。
   - 客户端错误（无 token 或 token 无效）返回 400：`Invalid captcha`。【F:handlers/auth.go†L54-L61】【F:handlers/auth.go†L159-L166】

## 相关配置项
- `TURNSTILE_ENABLED`：是否启用 Turnstile（默认 `true`）。【F:config/config.go†L26-L49】
- `TURNSTILE_SECRET_KEY`：Turnstile secret key（启用时必填）。【F:config/config.go†L26-L76】【F:config/config.go†L112-L120】
- `TURNSTILE_ALLOWED_HOSTNAME`：可选，限制 Turnstile 回调 hostname。【F:config/config.go†L26-L66】【F:utils/turnstile.go†L113-L124】

## 现状总结（要点）
- 注册/登录都依赖 Turnstile token，启用时未提供 token 会被视为客户端错误并拒绝请求。【F:handlers/auth.go†L31-L173】【F:utils/turnstile.go†L55-L58】
- 当前未启用 `action` 校验（传空字符串），可以在未来调整为传入 `register` / `login` 以增强防护。【F:handlers/auth.go†L51-L55】【F:handlers/auth.go†L143-L147】【F:utils/turnstile.go†L104-L111】
- 若 Turnstile 服务不可用或配置错误，接口返回 500 并记录服务端日志。【F:utils/turnstile.go†L48-L103】【F:handlers/auth.go†L54-L61】【F:handlers/auth.go†L159-L166】
