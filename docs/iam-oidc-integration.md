# 企业 IAM OIDC 对接说明（如意 AI 手机客户端）

> 对接信息由企业 IAM 管理员于 2026-11-08 提供；同日完成端点连通性与服务端换票链路实测。
> **本文档不包含任何 `client_secret` 或令牌**，密钥只存在于中继服务器的运行环境变量中。
> 当前状态：**服务端链路已打通，手机端登录链路尚未改造**（见 §8）。

## 1. 对接参数

| 项 | 值 | 说明 |
|---|---|---|
| issuer | `https://ai.thchengtay.com/iam` | 不带尾部斜杠；服务端 `DSH_IAM_OIDC_ISSUER` |
| client_id | `dsh-remote-mobile` | 服务端 `DSH_IAM_OIDC_CLIENT_ID`；手机端同名 dart-define |
| client_secret | **不记录** | 由 IAM 管理员在密钥渠道提供，只写入服务端 `DSH_IAM_OIDC_CLIENT_SECRET`；绝不进 App、代码库、文档、命令行历史或日志 |
| redirect_uri 白名单 | `dshgo://auth/callback` | **一字不差**；请求参数后面不能自行追加 `?xxx=yyy`，带了就失败 |
| response_type | `code` | 授权码模式 |
| scope | `openid profile email` | |
| PKCE | `S256` | token 端点强制校验 `code_verifier` |
| token 端点认证 | `client_secret_basic` | `Authorization: Basic base64(client_id:client_secret)` |
| id_token 签名 | `RS256` | `claims_supported` 含 `nonce`、`preferred_username`、`email` |
| refresh_token_ttl | `0` | 业务方不保存 IAM 令牌，无需签发 refresh_token |
| 测试账号 | `xubinbin` | LDAP 域账号 |
| 应用入口权限 | `mcp:gateway:access` | 已授予，用户角色直接 ALLOW |

## 2. 五个端点与调用方

| # | 步骤 | 调用方 | 方法与地址 |
|---|---|---|---|
| 1 | 自动发现 | App / 中继启动 | `GET {issuer}/.well-known/openid-configuration` |
| 2 | 发起登录（授权） | **手机系统浏览器** | `GET {issuer}/api/oidc/authorize` |
| 3 | 换取令牌 | **中继服务器** | `POST {issuer}/api/oidc/token` |
| 4 | 取用户信息（可选） | 中继服务器 | `GET {issuer}/api/oidc/userinfo` |
| 5 | 校验令牌签名 | 中继服务器 | `GET {issuer}/api/oauth/jwks`（以 `jwks_uri` 为准） |

2026-11-08 实测 `/.well-known/openid-configuration` 返回（HTTP 200），与管理员给出的地址全部一致：

```
issuer                    https://ai.thchengtay.com/iam
authorization_endpoint    https://ai.thchengtay.com/iam/api/oidc/authorize
token_endpoint            https://ai.thchengtay.com/iam/api/oidc/token
userinfo_endpoint         https://ai.thchengtay.com/iam/api/oidc/userinfo
jwks_uri                  https://ai.thchengtay.com/iam/api/oauth/jwks
response_types_supported  ["code"]
grant_types_supported     ["authorization_code","refresh_token"]
token_endpoint_auth_methods_supported  ["client_secret_basic","client_secret_post"]
code_challenge_methods_supported       ["S256"]
id_token_signing_alg_values_supported  ["RS256"]
```

**实际运行以 discovery 返回为准，不要写死 `jwks_uri`。** 密钥轮换后地址不变、密钥内容会变，标准库会按 `kid` 重新取。当前服务端实现（`apps/server/src/iam-oidc.ts`）：discovery 缓存 10 分钟、JWKS 至少缓存 60 秒，从 `id_token` header 的 `kid` 选公钥；RS256 签名与 `iss` / `aud` / `exp` / `nonce` 全部校验，取 `sub` 作账号主键。换票成功后**不调用 userinfo、不保存 IAM 令牌**，符合 `refresh_token_ttl=0` 的约定。

> 实现差异：服务端是「首次换票时懒加载 discovery 并缓存」，不是启动时拉取；功能等价，超时 10 秒。

discovery 返回的 `token_endpoint` / `jwks_uri` 必须以 `issuer/` 开头，否则服务端抛 `foreign-endpoint` 拒绝换票——防止自动发现被劫持时把授权码送出别域。

## 3. 发起登录的完整地址

```
https://ai.thchengtay.com/iam/api/oidc/authorize
?response_type=code
&client_id=dsh-remote-mobile
&redirect_uri=dshgo%3A%2F%2Fauth%2Fcallback
&scope=openid%20profile%20email
&state=<随机串>
&nonce=<随机串>
&code_challenge=<PKCE challenge>
&code_challenge_method=S256
```

`state`、`nonce` 每次登录重新生成；`code_challenge = BASE64URL(SHA256(code_verifier))`，不带 `=` 填充。

## 4. 三条必须遵守的约定

1. **授权地址是「浏览器打开的网页」，不是 App 内部发 HTTP 请求调用的接口。** App 用系统浏览器（iOS `ASWebAuthenticationSession` / Android Custom Tabs）打开它；登录完成后系统带着结果跳回 `dshgo://auth/callback`。
2. **换票只能由中继服务器发起**：`POST` token 端点，用 `client_id + client_secret` 做 Basic 认证，表单参数 `grant_type=authorization_code`、`code`、`redirect_uri`、`code_verifier`。手机端只持有一次性 `code` 与自己生成的 `code_verifier`。
3. **验签地址取 `jwks_uri`，不要写死**：密钥轮换后地址不变、内容变，按 `kid` 重取公钥。

## 5. PKCE S256：防「取件码被半路截胡」

登录前 App 先造一对「谜题 + 答案」：

- **答案 `code_verifier`**：随机串，App 自己藏着，不随授权请求发出；
- **谜题 `code_challenge`**：答案的 SHA-256 哈希，发起登录时发给 IAM。

IAM 签发一次性 `code` 时只认谜题；换票方必须出示答案，IAM 验算「答案的哈希 == 之前给的谜题」才发 `id_token`。即便授权码在回跳途中被截获，没有 `code_verifier` 也换不到令牌。

## 6. 回跳：App 必须接住两种

| 情形 | 回跳形式 | 处理 |
|---|---|---|
| 成功 | `dshgo://auth/callback?code=xxx&state=xxx` | 先校验 `state` 与本次请求一致，再把 `code` + `code_verifier` + `redirectUri` + `nonce` 交给中继换票 |
| 失败 | `dshgo://auth/callback?error=access_denied&state=xxx` | 给用户提示「没有权限」，不发起换票 |

任何 `state` 不匹配的回调都要直接中止，不做换票。

## 7. 2026-11-08 实测记录

在只读、不落盘密钥、不执行真实用户登录的前提下完成：

| 检查 | 结果 | 结论 |
|---|---|---|
| `GET /.well-known/openid-configuration` | `200`，字段见 §2 | 端点与管理员提供值完全一致 |
| `GET /api/oauth/jwks` | `200`，1 把 RSA 公钥，`kid=8ce7eb8348424404`、`use=sig`、`alg=RS256`；Node `createPublicKey({format:'jwk'})` 导入成功 | 服务端 `jwks()` 的解析与按 `kid` 选键逻辑可用 |
| `GET /api/oidc/authorize`（用真实 client_id 与 `dshgo://auth/callback`） | `302 → /iam/sso/login?redirect=...&appCode=mcp-gateway&tenantCode=xxt` | **不是** `invalid_client` / `invalid_redirect_uri`，说明客户端注册与回调白名单已生效；未继续走账号登录 |
| `POST /api/oidc/token`（真实凭据 + 无效 code） | `400 {"error":"invalid_grant","error_description":"authorization code is invalid or expired"}` | Basic 客户端认证通过，失败原因仅是没有有效授权码 |
| 对照：`POST /api/oidc/token`（错误 secret） | `401 {"error":"invalid_client","error_description":"client authentication failed"}` | 反证上一条的 `invalid_grant` 确实来自有效凭据 |
| 服务端 `oidcConfigFromEnv` + `oidcIdentityFromCode` 直连真实 IAM | 配置解析 OK；真实 discovery → token 端点 → `AUTH_INVALID / 400 / invalid_grant` | 服务端换票代码与这套 IAM 兼容，错误分类正确 |
| `zod 4.6.7` 的 `z.string().url()` 解析 `dshgo://auth/callback` | 通过 | 服务端路由的 `redirectUri` 校验不会因自定义 scheme 报 400 |
| discovery 的 `foreign-endpoint` 校验 | 两个端点均以 `issuer/` 开头 | 通过 |

**结论：截止到「拿到有效授权码之前」，服务端与 IAM 的全链路已验证可通。** 剩下唯一未知是真实账号登录换出的 `id_token` 能否通过本地验签（`iss` / `aud` / `nonce`），需要手机端改造后做一次完整登录才能确认。

## 8. 代码契约核对

### 8.1 服务端：已对齐

- `server.ts` 已注册 `POST /api/v1/auth/iam/oidc`（三个 `DSH_IAM_OIDC_*` 齐全才注册，否则 404）。
- `iam-oidc.ts` 走 discovery → Basic 换票 → JWKS 验签 → `sub` 主键，不调用 userinfo、不留存 IAM 令牌。
- 路由入参是 `code` / `codeVerifier` / `redirectUri` / `nonce`，`redirectUri` 允许自定义 scheme。
- `client_secret` 只从服务端环境变量读取，手机端全程不接触。
- 单测 `apps/server/tests/iam-oidc.test.ts`：10/10 通过（本地假 IdP + 自签 RS256）。

### 8.2 手机端：存在冲突，尚未改造

仓库 `dsh-Go`（分支 `ios-ruyi-handoff`）当前实现是「App 内 WebView + 回环端口」，与本次 IAM 约定的「系统浏览器 + 自定义 scheme」不同，**按现状点击 IAM 登录必然失败**：

| # | 项 | 当前实现 | 要求 | 影响 |
|---|---|---|---|---|
| 1 | `redirectUri` | `IamLoginPage.redirectUri = http://127.0.0.1:8765/callback` | `dshgo://auth/callback`，一字不差 | IAM 拒绝授权请求（`invalid_redirect_uri`） |
| 2 | 登录容器 | `webview_flutter` + `HttpServer.bind(127.0.0.1, 8765)` 接回跳 | 系统浏览器 / `ASWebAuthenticationSession` / Custom Tabs | 与管理员约定不符；WebView 无法承载 `dshgo://` 回跳 |
| 3 | Android scheme | **已注册**：`LinkTrampolineActivity` 的 `VIEW/BROWSABLE` intent-filter 收全部 `dshgo://`，`LinksPlugin.take()` 原样把 URI 投递到 Dart | Dart 侧订阅深链并识别 `/auth/callback`，不要被分享码解析逻辑吞掉 | 原生链路可复用，缺 Dart 侧路由；`MainActivity` 有 `flutter_deeplinking_enabled=false`，需评估是否改用现有 Channel |
| 4 | iOS scheme | `Info.plist` 无 `CFBundleURLTypes` | 注册 `dshgo` URL Scheme | iOS 完全接不住回跳 |
| 5 | 编译参数 | `DSH_IAM_OIDC_ISSUER` 默认已是 `https://ai.thchengtay.com/iam`；`DSH_IAM_OIDC_CLIENT_ID` **默认空** | 构建时带 `--dart-define=DSH_IAM_OIDC_CLIENT_ID=dsh-remote-mobile` | 不带该参数时登录页直接显示「未配置」，release 下相关代码还会被 tree-shaking 剔除 |
| 6 | 中继地址 | 默认 `https://dsh.r2049.cn` | 联调指向测试中继 | 换票会发错服务器；用 `DSH_DEFAULT_RELAY` 或在 App 内改地址 |
| 7 | 失败回跳 | `_fail(error_description ?? error)`，界面显示 `access_denied` 原文 | 提示「没有权限」 | 文案不符合要求 |

补充：成功回跳的 `state` 校验、PKCE S256、换票参数（`code` / `codeVerifier` / `redirectUri` / `nonce`）在现有 `iam_login_page.dart` 与 `iam_oidc_client.dart` 中已经正确实现，改造时保留即可。

## 9. 联调步骤（待执行）

1. 中继服务器注入三个 `DSH_IAM_OIDC_*` 环境变量并重启（服务端**不自动读** `.env`，需 `node --env-file=.env dist/main.js` 或容器注入）。
2. 确认 `POST /api/v1/auth/iam/oidc` 不再返回 404。
3. 按 §8.2 改造手机端，带两个 dart-define 构建，中继地址指向测试机。
4. 用系统浏览器以 `xubinbin` 登录 → 回跳 `dshgo://auth/callback` → 换票 → 注册设备 → 验证 Host / Client 互相发现。
5. 验收点：`id_token` 本地验签通过（`iss` / `aud` / `nonce`）；`error=access_denied` 显示「没有权限」；`state` 不匹配的中止换票；中继日志无密钥泄露。

## 10. 安全约束（硬约束）

- `client_secret` **绝不**进手机端、dart-define、代码库、文档、命令行历史或日志；只在服务端运行环境的环境变量中。
- 管理员密钥绝不落手机端，联调时也不临时塞进去。
- `redirect_uri` 必须与白名单逐字一致，不能附加额外 query。
- `state` / `nonce` 每次登录重新生成并校验；PKCE `code_verifier` 不出 App。
- 业务方不保存 IAM 令牌（`refresh_token_ttl=0`），中继只签发自己的账号会话。
