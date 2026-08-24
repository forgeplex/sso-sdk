# SPA 直接登录（Authorization Code + PKCE）

仅当应用确实没有可托管登录态的后端时使用此方案。浏览器是公开客户端，不能保存 `client_secret`。

该示例使用 `oidc-client-ts` 处理 Discovery、state、nonce、PKCE、回调和 Token 生命周期。Go SDK 不会被打包进浏览器。

## 控制台配置

创建 SPA 应用并配置：

- callback URL：`http://localhost:4173/callback`
- logout URL：`http://localhost:4173/logout-callback`
- web origin：`http://localhost:4173`
- grant type：`authorization_code`
- token endpoint auth method：`none`
- Require PKCE：开启

不要为 SPA 创建或复制 `client_secret`。

## 运行

```bash
npm install
npm run dev
```

打开 `http://localhost:4173`，在页面中填写 Realm Issuer 和 SPA 应用的 Client ID。配置只保存在当前标签页的 `sessionStorage` 中。也可以复制 `.env.example` 为 `.env.local`，用环境变量预填配置。

不能双击 `index.html` 或通过 `file://` 打开：源码包含 TypeScript 和 npm 模块，必须由 Vite 编译并提供。

如果填写了 `VITE_API_URL`，示例会使用 Access Token 调用该 API。API 不能只解码 JWT，必须验证签名、`iss`、`aud`、有效期和所需 scope。生产系统还应结合 XSS 防护评估是否采用 BFF，以避免 Token 暴露给前端 JavaScript。
