# 本地启动与 Chrome RestMan 测试

本文使用 Chrome 的 RestMan 插件发送 HTTP 请求，不需要编写客户端脚本。
启动命令在项目根目录执行，需要 Java 17 或更新版本以及 Maven。

## 1. 构建并配置用户

在终端执行：

```shell
mvn clean verify
```

如果已经配置好 `config/users.json`，可以直接进入第 2 步。

否则，先生成密码哈希。在 Git Bash 中执行：

```shell
winpty java -Dloader.main=io.ytong.authserver.tools.PasswordHash -cp target/oauth2-auth-server-0.0.1-SNAPSHOT.jar org.springframework.boot.loader.launch.PropertiesLauncher
```

按提示输入两次相同的密码。输入时不会显示字符。
如果没有 `winpty`，打开 Windows 命令提示符（CMD），进入项目目录，执行：

```shell
java -Dloader.main=io.ytong.authserver.tools.PasswordHash -cp target/oauth2-auth-server-0.0.1-SNAPSHOT.jar org.springframework.boot.loader.launch.PropertiesLauncher
```

如果提示 `Run this utility from an interactive terminal`，说明 Java 没有检测到交互式控制台。
请使用上面的 Git Bash + `winpty` 或独立 CMD 窗口，不要在 IDE 输出面板运行，也不要通过管道传入密码。

在 IDE 中复制 `config/users.example.json`，将副本命名为 `config/users.json`。
把副本的 `passwordHash` 替换成刚生成的完整值，包括 `{bcrypt}` 前缀：

```json
{
  "schemaVersion": 1,
  "users": [
    {
      "id": "user-001",
      "username": "alice",
      "passwordHash": "这里填写完整的 {bcrypt}... 值",
      "enabled": true,
      "roles": ["USER"]
    }
  ]
}
```

上面的哈希是占位说明，必须替换。密码长度必须为 1–72 个 UTF-8 字节，不能包含 NUL。
`users.example.json` 是示例文件；应用默认读取的是 `users.json`。
修改用户文件后需要重启应用。不要提交本地用户文件。

## 2. 启动应用

在项目根目录执行，并保持终端运行：

```shell
java -jar target/oauth2-auth-server-0.0.1-SNAPSHOT.jar --spring.profiles.active=dev
```

出现 `Started AuthServerApplication` 表示启动成功。
服务地址为 `http://localhost:9000`。`dev` 使用临时签名密钥并允许本地 HTTP Session Cookie。
重启会清除 Session、授权状态和临时密钥。正式部署请参考 README 的密钥配置。

## 3. 准备 RestMan

在 Chrome 中打开 RestMan。后续操作都使用同一个 Chrome Profile 和同一个 RestMan 会话。

发送请求时：

1. 选择请求方法，例如 GET 或 POST。
2. 输入完整 URL。
3. 按需填写 Headers 和 Body。
4. 点击发送，检查状态码、响应头和响应体。

所有请求都使用 `localhost`，不要混用 `127.0.0.1`，因为 Cookie 按主机区分。
让 Chrome 管理 `JSESSIONID`，不要手动写死它；登录成功后 Session ID 会更新。

如果 RestMan 自动跟随重定向，可以在 RestMan 页面的 Chrome DevTools → Network 中勾选
Preserve log，重新发送请求，查看重定向链中每个请求的状态和 `Location` 响应头。
本项目不提供 `/app/login` 和 `/app/callback` 页面，这两个页面的最终错误不代表前面的授权请求失败。

## 4. 检查服务

在 RestMan 分别发送以下请求，不需要 Body 或 Authorization 请求头：

| 方法 | URL | 预期结果 |
| --- | --- | --- |
| GET | `http://localhost:9000/.well-known/oauth-authorization-server` | 200，OAuth2 元数据，issuer 为 `http://localhost:9000` |
| GET | `http://localhost:9000/oauth2/jwks` | 200，RSA 公钥信息，不包含私钥 |
| GET | `http://localhost:9000/api/auth/session` | 尚未登录时为 401 |

如果最后一个请求返回 200，说明当前 Chrome 会话已经登录。
可以先按第 9 步退出，或在 Chrome 中清除 localhost 的 Cookie 后重新开始。

## 5. 登录前发起授权请求

选择 GET，粘贴下面这一整行 URL：

```text
http://localhost:9000/oauth2/authorize?response_type=code&client_id=webapp&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fapp%2Fcallback&scope=demo.read&state=restman-test-001&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

不需要 Body 或额外请求头。原始响应应为：

```http
HTTP/1.1 302
Location: /app/login
```

服务端会在当前 Session 中保存待继续的授权请求。
如果 RestMan 自动跟随跳转，最终可能显示 `/app/login` 的 401；请在 Network 中查看最初的 302。
确认服务端设置的 `JSESSIONID` 在后续请求中被发送。

本例固定使用以下 PKCE 测试数据，两者必须配套：

| 参数 | 值 |
| --- | --- |
| code_verifier | `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` |
| code_challenge | `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` |
| code_challenge_method | `S256` |
| state | `restman-test-001` |

这些固定值仅用于手动测试。实际客户端必须为每次流程生成新的随机 verifier 和 state。
待继续请求在 5 分钟后过期；同一个 Session 中的新授权请求会替换旧请求。

## 6. 获取 CSRF token，然后登录

先发送：

```http
GET http://localhost:9000/api/auth/csrf
```

预期返回 200，例如：

```json
{
  "token": "这里是服务端返回的 token",
  "headerName": "X-CSRF-TOKEN"
}
```

复制返回的 token。然后新建登录请求：

| 项目 | 填写内容 |
| --- | --- |
| Method | POST |
| URL | `http://localhost:9000/api/auth/login` |
| Header | `Content-Type: application/json` |
| Header | 名称使用返回的 `headerName`，值使用返回的 `token` |
| Body 类型 | Raw JSON |

Body 填写：

```json
{
  "username": "alice",
  "password": "生成哈希时输入的原始密码"
}
```

将密码说明替换成你的真实测试密码，不要填写 bcrypt 哈希。
预期返回 200：

```json
{
  "user": {
    "id": "user-001",
    "username": "alice"
  },
  "continueUrl": "/api/auth/continue?id=服务端生成的ID"
}
```

如果 `continueUrl` 为 null，说明当前 Session 没有有效的待继续请求，请检查 Cookie 并重新从第 5 步开始。
登录只建立 Session，不会直接返回 access token。

可以再发送 GET `http://localhost:9000/api/auth/session`，预期返回 200 和 alice 的身份信息。

## 7. 继续授权并取得 code

复制登录响应中的 `continueUrl`，前面加上 `http://localhost:9000`，发送 GET。
例如，实际 ID 要使用登录响应中的值：

```text
http://localhost:9000/api/auth/continue?id=服务端生成的ID
```

预期的重定向链为：

1. 302 到原来的 `/oauth2/authorize?...`。
2. 302 到 `http://localhost:9000/app/callback?code=...&state=restman-test-001`。

如果 RestMan 不自动跟随重定向，就逐次对 `Location` 地址发送 GET，直到取得 callback 地址。
如果它自动跟随，就在 Network 的重定向链中查看 callback 对应的 `Location`。

确认 callback 路径等于注册的 `/app/callback`，并且 state 等于 `restman-test-001`。
复制 URL 中 `code` 参数的值。若它含有 `%` 转义，填写表单前先进行 URL 解码。
无需访问 callback 页面本身，它由单独的 webapp 提供。

继续链接只能使用一次。取得 code 后，请在 60 秒内执行下一步。

## 8. 用 code 换取 access token

在 RestMan 中新建请求：

| 项目 | 填写内容 |
| --- | --- |
| Method | POST |
| URL | `http://localhost:9000/oauth2/token` |
| Header | `Content-Type: application/x-www-form-urlencoded` |
| Body 类型 | URL-encoded 表单，不要选择 multipart 或 JSON |

表单字段：

| 字段 | 值 |
| --- | --- |
| grant_type | `authorization_code` |
| client_id | `webapp` |
| redirect_uri | `http://localhost:9000/app/callback` |
| code | 上一步取得的 code |
| code_verifier | `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` |

不需要 Basic Auth 或 client secret。不要把登录密码放在这个请求中。
如果 RestMan 没有 URL-encoded 表单模式，可以选择 Raw，并发送下面的内容，替换 `CODE`：

```text
grant_type=authorization_code&client_id=webapp&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fapp%2Fcallback&code=CODE&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Raw 模式中，code 如果包含保留字符，也必须进行 URL 编码。
预期返回 200，包含 `access_token`、`token_type: Bearer`、约 300 秒的有效期和 scope `demo.read`。
不会返回 refresh token。每个 code 只能成功交换一次。

本项目没有用于测试 Bearer token 的业务 API。业务资源服务器需要验证签名、issuer、
audience `demo-api`、有效期和 scope；仅解码 JWT 不等于验证签名。

## 9. 退出登录

登录会使旧 CSRF token 失效，因此先重新发送：

```http
GET http://localhost:9000/api/auth/csrf
```

使用新返回的 headerName 和 token，发送：

```http
POST http://localhost:9000/api/auth/logout
X-CSRF-TOKEN: 这里填写新返回的token
```

请求头名称以实际返回的 headerName 为准，不需要 Body。预期返回 204。
再发送 GET `http://localhost:9000/api/auth/session`，应返回 401。
退出只结束浏览器 Session；已经发出的 JWT 在使用本地签名验证的资源服务器上可能继续有效，直到过期。

## 10. 错误场景测试

| 测试 | 操作 | 预期 |
| --- | --- | --- |
| 缺少 CSRF | POST 登录时不发送 CSRF 请求头 | 403 |
| 密码错误 | 使用有效 CSRF，但填写错误密码 | 401，`invalid_credentials` |
| 登录字段不完整 | 使用有效 CSRF，JSON Body 填写 `{}` | 400，`invalid_request` |
| code 重复使用 | 成功换取 token 后，再发送相同 token 请求 | 400 OAuth 错误；可能使关联授权失效 |
| PKCE 不支持 | 第 5 步 URL 的 `code_challenge_method=S256` 改为 `plain` | 400 |
| redirect_uri 未注册 | 第 5 步改成其他回调地址 | 400，不跳转到该地址 |
| 继续链接重复使用 | 已登录时，再次访问已消费的 continueUrl | 400，`authorization_expired` |
| 未认证的 introspection | POST `/oauth2/introspect`，URL-encoded Body 为 `token=fake` | 401 |

默认 `webapp` 是公共客户端，不能作为 confidential client 认证到 introspection/revocation。
成功的 introspection/revocation 需要另行配置带 bcrypt secret hash 的 confidential client，
再使用该客户端自己的授权码流程取得 token。已有集成测试覆盖此场景。

## 常见问题

| 问题 | 检查内容 |
| --- | --- |
| `AuthProperties.users()` 为 null | 检查 `target/classes/application.yaml` 是否存在；执行 `mvn resources:resources` 并在 IDE 重新加载 Maven 项目；用 dev profile 启动，不要只加载 application-dev.yaml |
| `User directory missing or invalid` | 确认存在 `config/users.json`，而不是只编辑 example；哈希完整，JSON 字段和角色正确 |
| 启动要求 keystore/password | 本地测试需要激活 dev profile |
| 登录 403 | CSRF token 和 Cookie 必须来自同一个会话；登录后需要重新获取 CSRF |
| 登录 401 | 检查原始密码、用户名和 enabled；修改 users.json 后重启 |
| 登录后授权仍跳转登录页 | 检查 JSESSIONID 是否发送，登录后是否接受了更新的 Cookie，主机是否一直使用 localhost |
| 登录 429 | 滑动 60 秒内，每用户名最多 10 次，每来源地址最多 60 次；停止重试并等待至少 60 秒 |
| continueUrl 过期或为空 | 检查 Session，重新从第 5 步开始 |
| token 请求 400 | code 是否过期或已使用，verifier 是否一致，redirect_uri 和 client_id 是否匹配 |
| `/app/login` 或 `/app/callback` 页面失败 | 本项目不提供这些页面；通过 Network 检查前面的 302 和 Location |

完成后，在运行服务的终端按 Ctrl+C 停止应用。不要分享包含密码、Session Cookie 或 access token 的截图和日志。
