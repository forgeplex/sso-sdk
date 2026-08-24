# Forgeplex SSO 对接示例

先按系统形态选择方案，不要仅因为都是同一个业务系统就复用同一个客户端。

| 方案 | 适用场景 | SSO 应用类型 | Secret 放置位置 | 示例 |
| --- | --- | --- | --- | --- |
| Go 后端托管登录 | 管理后台、商城、传统 Web、BFF | 常规 Web 应用（机密客户端） | 仅后端环境变量 | [web-backend](web-backend/) |
| SPA 直接登录 | 没有业务后端的纯前端应用 | SPA（公开客户端） | 不允许存在 Secret | [spa-pkce](spa-pkce/) |
| 服务间调用 | 定时任务、运维程序、内部服务 | 机器对机器应用 | 仅服务端 Secret 管理系统 | [machine-to-machine](machine-to-machine/) |

## 共同前置条件

1. 在租户下选定目标 Realm。Realm 决定 issuer、Discovery、JWKS 和签名密钥。
2. 为每个运行端创建独立应用，不要让前台、后台和任务程序共享凭据。
3. 精确登记 callback、logout URL 和 web origin；生产环境使用 HTTPS。
4. 只授予必要的 API audience 和 scopes。
5. 客户端从 `{issuer}/.well-known/openid-configuration` 做 Discovery，不要手写授权、Token 或 JWKS 路径。

## 怎么选择

- 系统存在 Go 后端：优先使用 [web-backend](web-backend/)。浏览器只拿 HttpOnly Session Cookie，OIDC Token 不进入前端 JavaScript。
- 系统确实是无后端 SPA：使用 [spa-pkce](spa-pkce/)，必须启用 PKCE，且应用的 token endpoint auth method 为 `none`。
- 程序不代表用户，只代表自身执行管理任务：使用 [machine-to-machine](machine-to-machine/)，不要模拟用户登录。

如果业务前端需要调用自己的 API，推荐由 Go 后端验证登录并建立 Session；若 SPA 必须携带 Access Token 调 API，API 仍需独立校验 token 的签名、`iss`、`aud`、有效期和 scope。
