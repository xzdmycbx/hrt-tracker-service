# 注册与登录验证码（前端请求文档）

本文档面向前端，说明注册与登录接口如何携带 Turnstile 验证码 token。

## 接口概览
- 注册：`POST /api/auth/register`
- 登录：`POST /api/auth/login`

这两个接口在校验用户名/密码之前，会校验 `turnstile_token`（Cloudflare Turnstile）。当后端启用 Turnstile 时，缺少 token 会返回 400。禁用 Turnstile 时，token 可为空。【F:handlers/auth.go†L31-L173】【F:utils/turnstile.go†L38-L58】

## 请求头
- `Content-Type: application/json`

## 注册请求
**URL**
```
POST /api/auth/register
```

**Body**
```json
{
  "username": "user_123",
  "password": "your_password",
  "turnstile_token": "<turnstile_response_token>"
}
```
- `turnstile_token` 为 Turnstile widget 返回的 token。
- 后端目前不强制校验 Turnstile 的 `action` 字段，但代码注释建议前端设置 `data-action="register"` 以便未来启用 action 校验。【F:handlers/auth.go†L17-L55】【F:utils/turnstile.go†L104-L111】

**成功响应（200）**
```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "expires_in": 3600
}
```
【F:handlers/auth.go†L96-L124】

**失败响应**
- 400 `Invalid captcha`：token 为空或无效（启用 Turnstile 时）。【F:handlers/auth.go†L54-L61】【F:utils/turnstile.go†L55-L58】
- 400 `Invalid request body`：请求体缺字段或格式错误。【F:handlers/auth.go†L33-L36】
- 500 `Failed to verify captcha`：Turnstile 服务不可用或服务端配置错误。【F:handlers/auth.go†L54-L61】【F:utils/turnstile.go†L48-L103】

## 登录请求
**URL**
```
POST /api/auth/login
```

**Body**
```json
{
  "username": "user_123",
  "password": "your_password",
  "turnstile_token": "<turnstile_response_token>"
}
```
- `turnstile_token` 为 Turnstile widget 返回的 token。
- 后端目前不强制校验 Turnstile 的 `action` 字段，但代码注释建议前端设置 `data-action="login"` 以便未来启用 action 校验。【F:handlers/auth.go†L126-L147】【F:utils/turnstile.go†L104-L111】

**成功响应（200）**
```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "expires_in": 3600
}
```
【F:handlers/auth.go†L189-L216】

**失败响应**
- 400 `Invalid captcha`：token 为空或无效（启用 Turnstile 时）。【F:handlers/auth.go†L159-L166】【F:utils/turnstile.go†L55-L58】
- 400 `Invalid request body`：请求体缺字段或格式错误。【F:handlers/auth.go†L128-L131】
- 401 `Invalid username or password`：账号或密码错误。【F:handlers/auth.go†L169-L188】
- 500 `Failed to verify captcha`：Turnstile 服务不可用或服务端配置错误。【F:handlers/auth.go†L159-L166】【F:utils/turnstile.go†L48-L103】

## Turnstile 开关与注意事项（给前端的提示）
- `TURNSTILE_ENABLED=false` 时，后端会跳过验证，`turnstile_token` 允许为空。【F:utils/turnstile.go†L38-L46】
- `TURNSTILE_ENABLED=true` 时，前端必须携带 `turnstile_token`，否则返回 400。【F:utils/turnstile.go†L55-L58】
- 如需绑定域名校验，可配置 `TURNSTILE_ALLOWED_HOSTNAME`；这会要求 Turnstile 返回的 `hostname` 与配置一致。【F:utils/turnstile.go†L113-L124】
