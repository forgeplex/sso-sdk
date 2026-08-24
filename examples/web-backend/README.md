# Go 后端托管登录（推荐）

该示例展示浏览器、Go 后端与 Forgeplex SSO 的完整登录链路：

```text
浏览器 -> /login -> Go 后端生成 state/nonce/PKCE -> SSO
浏览器 <- /callback <- Go 后端换取并校验 Token <- SSO
浏览器 -> /me -> Go 后端 Session -> 用户资料
```

OIDC Token、PKCE verifier 和登录态都保存在后端。浏览器 Cookie 只包含随机、不透明的 Session ID。

## 控制台配置

创建常规 Web 应用并配置：

- callback URL：`http://localhost:3000/callback`
- logout URL：`http://localhost:3000/`
- grant type：`authorization_code`
- token endpoint auth method：`client_secret_post`（或按控制台配置改为 `client_secret_basic`）
- Require PKCE：开启

## 运行

```bash
export SSO_ISSUER='http://point-market.localhost:8081/'
export SSO_CLIENT_ID='YOUR_CLIENT_ID'
export SSO_CLIENT_SECRET='YOUR_CLIENT_SECRET'
export SSO_REDIRECT_URL='http://localhost:3000/callback'
export SSO_POST_LOGOUT_REDIRECT_URL='http://localhost:3000/'
go run ./examples/web-backend
```

打开 `http://localhost:3000`。

## 生产环境注意事项

示例为便于阅读使用进程内 Session Store。多实例部署时应替换为 Redis 或数据库，并设置过期清理、加密备份和服务端吊销。生产环境必须使用 HTTPS，并保持 Cookie 的 `Secure`、`HttpOnly` 和合适的 `SameSite` 设置。
