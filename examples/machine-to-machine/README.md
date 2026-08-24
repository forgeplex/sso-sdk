# 机器对机器调用 Management API

适用于定时任务、同步程序和内部服务。该流程没有用户，也不应跳转登录页面。

## 控制台配置

1. 在目标 Realm 创建“机器对机器”应用。
2. 在“机器授权”中关联 `SSO Management API`。
3. 只授予所需 scope；本例读取应用列表，需要 `read:clients`。
4. 保存只显示一次的 `client_secret`，放入服务端 Secret 管理系统。

## 运行

```bash
export SSO_ISSUER='http://point-market.localhost:8081/'
export SSO_MANAGEMENT_URL='http://localhost:8082'
export SSO_AUDIENCE='http://point-market.localhost:8081/api/v2/'
export SSO_REALM_ID='YOUR_REALM_ID'
export SSO_CLIENT_ID='YOUR_M2M_CLIENT_ID'
export SSO_CLIENT_SECRET='YOUR_M2M_CLIENT_SECRET'
go run ./examples/machine-to-machine
```

生产环境认证服务和管理服务同源时，`SSO_MANAGEMENT_URL` 可以省略。`SSO_AUDIENCE` 是租户 Management API 标识，不一定等于当前 Realm issuer。
