# Forgeplex SSO Go SDK

Go SDK 同时覆盖两类服务端集成：

- OIDC 登录：Discovery、Authorization Code + PKCE、state / nonce、ID Token 验证、UserInfo 与退出地址。
- Management API：通过 `client_credentials` 自动获取并缓存管理令牌，为 Realm 内资源自动携带显式 `realm_id`。

## 安装

```bash
go get github.com/forgeplex/sso-sdk
```

## 接入用户登录

在控制台创建“常规 Web 应用”，登记精确的回调地址，然后在服务启动时完成 Discovery：

```go
login, err := sso.NewOIDC(context.Background(), sso.OIDCConfig{
	IssuerURL:              "https://customer.auth.example.com/",
	ClientID:               os.Getenv("SSO_CLIENT_ID"),
	ClientSecret:           os.Getenv("SSO_CLIENT_SECRET"),
	RedirectURL:            "https://app.example.com/callback",
	TokenEndpointAuthMethod: "client_secret_post",
})
```

登录入口生成一次性 state、nonce 与 PKCE verifier。完整 `AuthorizationRequest` 必须保存在应用自己的服务端 session 中：

```go
request, err := login.BeginLogin(sso.AuthorizationOptions{})
// 保存 request 到服务端 session，然后 302 到 request.URL。
```

回调页从服务端 session 取回同一份 request，再完成交换与验证：

```go
session, err := login.Exchange(ctx, code, returnedState, request)
if err != nil {
	// 拒绝本次登录。
}
fmt.Println(session.Subject, session.Claims["email"])
```

`Exchange` 返回前已经验证签名、issuer、audience、过期时间、state、nonce，以及 ID Token 声明了 `at_hash` 时的 access token 绑定。

## 调用 Management API

### 准备配置

在控制台中：

1. 进入目标身份域，创建“机器对机器”应用并保存只显示一次的 `client_secret`。
2. 在“机器授权”中选择该应用与 `SSO Management API`。
3. 只授予程序实际需要的 scopes，例如读取应用只需要 `read:clients`。

### 使用

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	sso "github.com/forgeplex/sso-sdk"
)

func main() {
	client, err := sso.New(sso.Config{
		IssuerURL:    "https://customer.auth.example.com/",
		Audience:     "https://customer.auth.example.com/api/v2/",
		RealmID:      "YOUR_REALM_ID",
		ClientID:     os.Getenv("SSO_CLIENT_ID"),
		ClientSecret: os.Getenv("SSO_CLIENT_SECRET"),
		Scopes:       []string{"read:clients"},
	})
	if err != nil {
		log.Fatal(err)
	}

	page, err := client.Applications.List(context.Background(), sso.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}
	for _, application := range page.Items {
		fmt.Println(application.Name, application.ClientID)
	}
}
```

本地开发中 `authd` 与 `mgmtd` 使用不同端口时，再设置 `ManagementURL`：

```go
ManagementURL: "http://localhost:8082",
```

如果机器应用位于非默认身份域，`IssuerURL` 使用该身份域的 issuer，而 `Audience` 仍使用租户默认身份域的 `{issuer}api/v2/`。这是租户级 Management API 与 Realm 级签名密钥之间的明确边界，不要把两者写成同一个值。

### 当前已类型化的资源

- 应用：列表、详情、创建、更新、删除
- API：列表、详情、创建、更新、删除
- 连接：列表、详情
- 用户：列表、详情
- 角色：列表、详情
- 身份域：列表、详情、创建、更新、删除

尚未类型化的新接口可以通过 `Client.Do` 调用。它仍会复用相同的令牌缓存、错误模型和 Realm 上下文。
