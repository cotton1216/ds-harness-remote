# 企业 IAM OIDC 对接说明（如意 AI 手机客户端）

> 对接信息由企业 IAM 管理员于 2026-11-08 提供；同日完成端点连通性与服务端换票链路实测，并按约定改造了手机端登录链路。
> **本文档不包含任何 `client_secret` 或令牌**，密钥只存在于中继服务器的运行环境变量中。
> 当前状态：**服务端 ↔ IAM 链路、手机端 OIDC 授权与深链回跳链路均已在真机闭环**（2026-11-08 下午，见 §8.4 / §8.5）；**唯一阻塞是线上中继尚未注入 OIDC 配置** —— 真机换票返回 404 `METHOD_NOT_FOUND`，App 按预期提示「中继尚未配置 IAM 单点登录」。真实 `id_token` 验签与 Host/Client 发现待运维配置完成后验收（§9）。

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
| 本地实际启动 `apps/server`（三个真实 OIDC 环境变量注入，`127.0.0.1:18080`），`POST /api/v1/auth/iam/oidc` 提交无效 code | `401 {"error":{"code":"AUTH_INVALID",...}}`；`GET` 同路径 `404`；服务日志无密钥 | 路由注册 → discovery → Basic 换票 → 错误映射整链路可通，不再是「未配置」的 404 |

**结论：截止到「拿到有效授权码之前」，服务端与 IAM 的全链路（含本地实际起服务）已验证可通。** 剩下唯一未知是真实账号登录换出的 `id_token` 能否通过本地验签（`iss` / `aud` / `nonce`），需要手机端改造后做一次完整登录才能确认。

> 本地验证说明：服务只在 `127.0.0.1` 临时启动，环境变量在进程内注入、未写入任何文件，验证完立即停止；`dataFile` 指向 `/tmp`，测试账号口令为一次性占位值。该验证**不等于**已把配置部署到线上中继 `https://118.196.18.181:8443`。

## 8. 代码契约核对

### 8.1 服务端：已对齐

- `server.ts` 已注册 `POST /api/v1/auth/iam/oidc`（三个 `DSH_IAM_OIDC_*` 齐全才注册，否则 404）。
- `iam-oidc.ts` 走 discovery → Basic 换票 → JWKS 验签 → `sub` 主键，不调用 userinfo、不留存 IAM 令牌。
- 路由入参是 `code` / `codeVerifier` / `redirectUri` / `nonce`，`redirectUri` 允许自定义 scheme。
- `client_secret` 只从服务端环境变量读取，手机端全程不接触。
- 单测 `apps/server/tests/iam-oidc.test.ts`：10/10 通过（本地假 IdP + 自签 RS256）。

### 8.1.1 统一身份（2026-11-09 更新）

中继不再用 IAM 数字 `id`，也不再信任顶层或调用方传入的 `sub`。已核对
`ai-server-new` origin/main `bdf0b88d6`：真实 router 是
`authenticated.Group("/user")` + `GET("/profile")`，因此固定调用：

```
GET {base}/api/v1/user/profile
Authorization: Bearer <access_token>

{ "code": 0, "data": {
    "id": 9, "email": "...", "username": "...",
    "identities": { "oidc": {
      "provider": "oidc", "bound": true,
      "subject": "usr_xxx", "issuer": "https://iam..."
    } }
} }
```

字段来自 `service.UserIdentitySummary`（`identities` / `oidc` 的 JSON tag 已核实）；
其中 OIDC 的 `subject` 取 `ProviderSubject`、`issuer` 取 `ProviderKey`（即
`provider_key` 就是 issuer）。

登录响应没有 `subject`，所以口令登录必须先 `POST /api/v1/auth/login` 拿到
`access_token`，再调用上面的 profile 接口确定身份。

服务端规则（`apps/server/src/iam.ts`）：

- 只读严格嵌套的 `data.identities.oidc`，要求 `provider === "oidc"`、`bound === true`；
  缺失、空串、含空白/控制字符或 `***` 掩码的 `subject` 一律拒绝且原样保留合法值。
- `issuer` 必须与服务端可信 issuer **精确相等**（不做前缀/同域比较），否则拒绝。
- 可信 issuer 取 `DSH_IAM_ISSUER`，未设置时回退 `DSH_IAM_OIDC_ISSUER`；配置了
  `DSH_IAM_BASE` 却两者都没有时服务启动失败，绝不接受 profile 自称的 issuer。
- profile 请求固定服务端 base 与路径，并设置 `redirect: "manual"`：3xx 直接按
  上游不可用拒绝，避免 `Authorization` 头被带到其他源。
- 不回退数字 `id`，也不接受请求 JSON 中的 `sub`。

三条入口共用同一个账号键：

```
account = "iam:" + sha256(JSON.stringify([issuer, subject]))
```

`/api/v1/auth/iam`（桌面 token）、`/api/v1/auth/login`（口令）与
`/api/v1/auth/iam/oidc`（id_token 验签）都调用同一个 `externalIdentity()`，
所以同一 `(issuer, subject)` 必然落到同一个 `accountId`；issuer 参与哈希，
不同 issuer 的同名 subject 不会串号。旧开发数据的 `iam:<数字>` 不做迁移。

OIDC-only 部署（只配 `DSH_IAM_OIDC_*`、不配 `DSH_IAM_BASE`）现在允许无本地账号启动，
且 Store 的外部身份开关在 OIDC 配置存在时也打开，重启后账号不会被本地账号扫描停用。
本地口令账号仍然保留为 break-glass，不引入特权，也不自动清理任何数据。

集成测试 `apps/server/tests/iam-unified-identity.test.ts` 使用假 AI-Server、真 RS256
假 IdP 与真中继 HTTP 服务（无 mock 注册结论）：三条入口同账号、不同 subject 隔离、
不同 issuer 拒绝、伪造 token、缺失/掩码 subject、未绑定、issuer 不匹配、profile
重定向不跟随（下游 0 次命中）、OIDC-only 重启后账号仍可用。

### 8.2 手机端：2026-11-08 已按约定改造

仓库 `dsh-Go`（分支 `ios-ruyi-handoff`）。改造前是「App 内 WebView + 回环端口」，与管理员约定的「系统浏览器 + 自定义 scheme」冲突，点 IAM 登录必然失败；下表是**改造后**状态：

| # | 项 | 改造前 | 改造后 |
|---|---|---|---|
| 1 | `redirectUri` | `http://127.0.0.1:8765/callback` | 常量 `iamOidcRedirectUri = 'dshgo://auth/callback'`，授权请求与换票请求共用，逐字一致、不附加 query |
| 2 | 登录容器 | `webview_flutter` + `HttpServer.bind(127.0.0.1, 8765)` | 外部系统浏览器：Android 由 `dsh/app` 原生通道优先交给 Chromium 内核浏览器（见 §8.5），无该通道时回退 `url_launcher` 的 `LaunchMode.externalApplication`；iOS 直接用系统 Safari。WebView 与回环监听整体删除，页面改为状态页 + 「在系统浏览器中继续登录」按钮 |
| 3 | Android 回跳 | 原生已注册 `dshgo`，Dart 侧缺路由 | 复用 `LinkTrampolineActivity` → `LinksPlugin`（`dsh/links`）；新增常驻 `IamLinkHost` 注册 `auth/callback` handler，只吃 IAM 回跳，不吞分享码/页面链接；`flutter_deeplinking_enabled=false` 保持不变，避免重复投递 |
| 4 | iOS 回跳 | **完全接不住**：无 URL Scheme，也没有原生投递通道 | `Info.plist` 加 `CFBundleURLTypes`（`dshgo`）；`AppDelegate.swift` 新增 `DshLinksChannel`（与 Android 同契约：`ready` 之前缓冲、之后推 `link`，双入口按 URL 去重）；`SceneDelegate.swift` 接 `openURLContexts`，AppDelegate 的 `application(_:open:options:)` 兜底 |
| 5 | 编译参数 | `DSH_IAM_OIDC_CLIENT_ID` 默认空，不带就登录不了 | 默认 `dsh-remote-mobile`（公开标识，不是密钥），仍可用 dart-define 覆盖；issuer 默认已是管理员给的值 |
| 6 | 中继地址 | 默认 `https://dsh.r2049.cn` | 默认值不动；联调构建带 `DSH_DEFAULT_RELAY`，或在 App 内改中继地址 |
| 7 | 失败回跳 | 显示 `access_denied` 原文 | 单独分类并提示「没有权限：该账号未被授权使用如意 AI…」；其它错误显示「IAM 登录失败：\<error\>：\<description\>」，都不发 code |
| 8 | 冷启动 | loopback 监听随页面销毁 | 深链 handler 常驻 home shell；浏览器登录期间进程若被回收，`code_verifier` 只存内存已丢失，回跳记成 orphan，页面提示「登录已中断，请重新发起」，绝不用对不上的 verifier 换票 |

保留不改：成功回跳的 `state` 校验、PKCE S256、换票四参数（`code` / `codeVerifier` / `redirectUri` / `nonce`）、404 与无效码的不同提示。

**与 RFC 8252 的取舍**：全程用外部系统浏览器，不引入 `ASWebAuthenticationSession` / Custom Tabs SDK（会新增依赖与 iOS 构建面）。同样满足「不在 App 内 WebView 里输入企业口令」，SSO 会话保存在系统浏览器；Android 只是额外指定用哪个系统浏览器（§8.5），不改变回跳协议与服务端。后续若要更贴合 RFC 8252，可只替换打开方式。

### 8.3 改造后的验证（2026-11-08）

| 检查 | 结果 |
|---|---|
| `flutter analyze --no-pub`（`app/` 全仓） | **0 issues**（顺带清掉 `integration_test/remote_connect_test.dart` 4 个既有 lint） |
| `flutter test test/remote/iam_oidc_flow_test.dart test/remote/iam_oidc_client_test.dart` | **13/13 通过**：授权地址参数与逐字编码、PKCE S256、state 校验、access_denied 分类、其它错误、深链不吞别的链接、换票报文字段、404 / 401 / 无效响应 |
| `tool/l10n_merge.py` + `flutter gen-l10n` | 47 个 part / 5479 key 校验通过，中英文案重新生成 |
| `flutter build ios --simulator --debug --no-codesign --no-pub` | **通过**（`Runner.app`），Swift 深链通道编译无误；真机签名与系统浏览器回跳仍需实机验收 |
| `flutter build apk --debug --flavor arm64 --target-platform android-arm64 --no-pub` | **通过**，产出 `app/build/app/outputs/flutter-apk/app-arm64-debug.apk`，已带 `DSH_DEFAULT_RELAY` 指向测试中继，可直接装到 Android 设备 |
| 真机端到端 | **已走到换票并拿到明确结果**：`1.0.9+11081315` 装在开发机后，点 IAM 登录 → 系统浏览器打开 → 立即回跳 `dshgo://auth/callback?code=…&state=…` → `LinkTrampolineActivity` 投递成功 → App 换票 → 中继 404 → 页面显示「中继尚未配置 IAM 单点登录，请联系管理员。」（§8.5）。**App 侧全通**；线上中继未注入 OIDC 配置是唯一阻塞 |

### 8.4 真机联调修复：Android 深链回跳丢失（2026-11-08 下午）

在开发测试机（`M2102K1AC` / HyperOS 2.0 / Android 14）上首次真机点 IAM 登录时发现：系统浏览器输完账密回到 App 后，页面一直停在「IAM 账号登录」，反复点「重新发起登录 / 在系统浏览器中继续登录」只会来回跳转，5 分钟后显示「等待登录超时，请重新发起」。**这不是 OIDC 参数或中继配置问题，是 App 的 Android 深链通道整体失效**：连自带的 `dshgo://open/forum`、故意不存在的 `dshgo://nobody-xyz/nope`（本应弹「无法打开这个链接」）都毫无反应。该缺陷早于本次 OIDC 改造存在。

两个根因与修复（`dsh-Go` 提交 `8bf626a`）：

| # | 根因 | 证据 | 修复 |
|---|---|---|---|
| 1 | `LinkTrampolineActivity` 的 `NEW_TASK \| CLEAR_TOP \| SINGLE_TOP` 在该 OEM 上让 ActivityStarter 返回 `START_TASK_TO_FRONT (2)`，只把 task 前置，不派发 `NewIntentListener` | logcat 中 `START ... dat=dshgo://auth/... → LinkTrampolineActivity` 后转 MainActivity 为 `result code=2`；直接投 MainActivity 为 `result code=3` | 去掉 `CLEAR_TOP`；`MainActivity.onNewIntent` 增加 `LinksPlugin.deliverFromHost(intent)` 兜底，按 intent identity 去重 |
| 2 | `LinksPlugin.ready` 恒为 false，链接全部堆在原生 `pending`；Dart 的 `AppLinks` 只在 home_shell 挂载时懒创建，`_ready()` 单次调用失败被静默吞掉 | 日志 `deliver ready=false event={uri=...}`；走完首次引导进入 home_shell 后才出现 `ready: flushing` | `AppLinks._ready()` 重试 8 次 × 250ms，并加全链路 `DshLinks` 诊断日志 |

**验证**：`flutter analyze --no-pub` 0 issues；重出 `1.0.9+11081258` arm64 debug 包（仍带 `DSH_DEFAULT_RELAY`），真机上发 `dshgo://open/forum` 得到 `deliver ready=true → native link → arrived`，论坛页正常打开。冷启动回跳仍走原生 `pending` → `ready` flush 的既有机制；App 在浏览器期间被回收会按设计提示「登录已中断，请重新发起」（`code_verifier` 只在内存）。

> 排障注意：`am force-stop` 会让该 App 回到 4 步首次引导，引导期间 home_shell 未挂载、`ready` 不会到达，别据此误判深链仍坏。

> 运行 dsh-Go 的 Flutter 测试需要 `DSH_TEST_FONT_DIR=/Users/binny/dev/fonts/noto-cjk`，并清掉 `HTTP(S)_PROXY`（否则 `flutter_tester` 的本地 WebSocket 被代理拦截）。这只是本机环境，不是代码约束。

### 8.5 真机联调修复：默认浏览器夸克白板（2026-11-08 下午）

深链修好后再测，出现新现象：点「IAM 账号登录」跳到系统默认浏览器**夸克**，整页纯白、地址栏是正确的 authorize URL，没有任何表单或报错，用户没法输入账密。

定位过程（与 IAM 参数无关）：

| 检查 | 结果 |
|---|---|
| 从 `dumpsys activity activities` 取出浏览器收到的完整 URL | `client_id` / `redirect_uri` / `scope` / `state` / `nonce` / `code_challenge` 全部正确，与 §3 一致 |
| `curl -k --noproxy '*'` 直接请求该 URL | `302` → `/iam/sso/login?redirect=…&appCode=mcp-gateway&tenantCode=xxt`；跟随重定向得到 `200 text/html`（1561 字节） |
| SSO 页面内容 | Vue SPA 骨架，渲染依赖 `/iam/static/js/index-*.js`（ES module + `crossorigin`）与两个 CSS；这些静态资源逐个 curl 均 `200`，大小 1.1MB / 1.0MB / 692KB |
| 对照：`am start -a VIEW -d <同一 URL> -p com.android.chrome` | **Chrome 正常显示**「欢迎回来 / 用户名 / 密码 / 进入工作台」 |
| 设备默认浏览器 | `cmd package resolve-activity` 指向 `com.quark.browser/com.ucpro.MainActivity`；日志里夸克以 `LAUNCH_SINGLE_TASK` 复用 task（`result code=3`） |

结论：**夸克内核渲染不了 IAM 的 Vue 登录页**，白板既不是 URL 拼错，也不是 IAM 服务或中继的问题。

修复（`dsh-Go` 提交 `4ab1150`）：

- `MainActivity` 的既有 `dsh/app` 通道新增 `openSignInBrowser(url)`：按 `com.android.chrome` → Beta / Dev → Edge 的顺序 `setPackage` 显式打开**外部系统浏览器**；都不存在才回退系统默认。仍是浏览器而非 WebView，OIDC 安全属性不变，回跳继续走 `dshgo://` 深链。
- `IamLoginPage._launchBrowser()` 先调该通道；`MissingPluginException` / `PlatformException` / 返回 false 时回退 `url_launcher` 的 `LaunchMode.externalApplication`。iOS、桌面、widget 测试不受影响，仍用系统 Safari / 原行为。
- 收到回跳时调用项目已有的 `appForegroundProvider`（`dsh/app bringToFront`），把结果页从浏览器上方带回前台，避免「换票其实结束了但仍停在浏览器」。

**验证**（`1.0.9+11081315`，仍带 `DSH_DEFAULT_RELAY` 指向测试中继）：`flutter analyze --no-pub` 0 issues、IAM 单测 13/13；真机点登录后日志依次是 `START … cmp=com.android.chrome/…ChromeTabbedActivity` → `START … dat=dshgo://auth/… cmp=…LinkTrampolineActivity` → MainActivity 转发 + `bringToFront`，App 显示「中继尚未配置 IAM 单点登录，请联系管理员。」—— 白板与来回跳转都消失，App 侧链路闭环。

> 两条真机注意：① MIUI 首次会弹「启动应用：如意 AI 想要打开 Chrome，是否允许?」，点一次「始终允许」即可，这是显式跨应用启动的链式启动确认；② 浏览器里已有 SSO 会话时，authorize 会**立刻 302 回跳**而不再显示表单，看到浏览器一闪而过属正常；会话失效后才会要求 `xubinbin` 本人输入口令（该表单已在 Chrome 中确认可正常显示）。

## 9. 联调步骤（中继侧已完成，剩真机端到端）

1. ~~按 §8.2 改造手机端~~ —— 2026-11-08 已完成，静态验证见 §8.3。
2. ~~**待办（运维）**：中继服务器注入三个 `DSH_IAM_OIDC_*` 环境变量并重启~~ —— **2026-11-08 14:12 已完成**，过程见 §9.1。注意线上原镜像不含 OIDC 代码，**只加变量重启无效，必须替换镜像**。
   - **Docker Compose 部署注意**：`apps/server/compose.yaml` 的 `environment:` 是白名单，只透传列出的变量。2026-11-08 已补上这三个键；线上若用的是更早的 compose 文件，光在 `.env` 里填值容器也收不到，必须同步更新 compose 并执行 `docker compose up -d --force-recreate`（重建容器才会重新读环境变量）。当前线上是裸 `docker run`，不走 compose。
   - 配置落在**中继服务端进程**，不是 IAM、也不是手机 App。「请联系管理员」指的是**这台中继的部署者**；自建中继就是自己，无需再找 IAM 管理员。IAM 侧（client 注册、回调白名单、账号权限、`client_secret` 发放）已全部完成。
3. ~~**待办（验收）**：确认 `POST /api/v1/auth/iam/oidc` 不再返回 404~~ —— **已完成**：POST 由 404 `METHOD_NOT_FOUND` 变为 400 `INVALID_MESSAGE`，GET 同路径仍 404，`/healthz` 200；直连 `127.0.0.1:18081` 与经 Nginx `8443` 结果一致。
4. 构建手机端。`client_id` / `issuer` 已有管理员给的默认值，联调只需把中继指到测试机；**Android 必须走仓库出包脚本**（它带 `--flavor` / `--target-platform`）：
   ```sh
   cd dsh-Go
   tooling/build-apk.sh --debug -f arm64 -- --dart-define=DSH_DEFAULT_RELAY=https://118.196.18.181:8443
   # 产物：app/build/app/outputs/flutter-apk/app-arm64-debug.apk
   # iOS：cd dsh-Go/app && flutter build ios --dart-define=DSH_DEFAULT_RELAY=https://118.196.18.181:8443
   ```
   直接 `flutter build apk` 不带 flavor 会因项目自定义 buildDir + ABI 分包报「Gradle 没有产出 .apk」（Gradle 其实产出了 `app-arm64-debug.apk`）；`--split-per-abi` 又与 `android/build.gradle.kts` 的 ndk abiFilters 冲突。两者都是既有构建配置，与 OIDC 无关。也可以在 App 的「连接如意 AI」里直接改中继地址，自建 IAM 再覆盖 `DSH_IAM_OIDC_ISSUER` / `DSH_IAM_OIDC_CLIENT_ID`。
5. 用系统浏览器以 `xubinbin` 登录 → 回跳 `dshgo://auth/callback` → 换票 → 注册设备 → 验证 Host / Client 互相发现。口令由本人在系统浏览器输入，不代填、不索取；浏览器已有 SSO 会话时会直接回跳（§8.5），要重走账密输入需先退出 IAM 会话。Android 上授权页由 App 交给 Chromium 内核浏览器，首次可能需点一次「始终允许」。
6. 验收点：`id_token` 本地验签通过（`iss` / `aud` / `nonce`）；`error=access_denied` 显示「没有权限」；`state` 不匹配的中止换票；iOS / Android 都能接住回跳；中继日志无密钥泄露。

### 9.1 线上中继切换记录（2026-11-08 14:12）

- **前提**：线上原镜像 `dsh-relay-multi:0.7.1` 的 `dist/` 里 `iam/oidc` 出现 0 次，只注入环境变量重启不会注册路由。新镜像 `dsh-relay-multi:0.8.0-oidc` 由 `apps/server/Dockerfile` 本地 buildx（`--platform linux/amd64`）构建，再 `docker save | ssh docker load` 传到服务器。
- **切换脚本**：服务器 `/root/dsh-relay-multi/switch-to-oidc.sh`（权限 700，脚本内不含任何密钥）。三个子命令：`check`（免密钥自检）、`switch`（默认）、`rollback`。它用 Docker Go template 的 NUL 分隔完整继承旧容器环境变量，停旧容器并改名 `dsh-relay-multi-pre-oidc` 保留，再以同名、同端口 `127.0.0.1:18081:8080`、同卷 `dsh-relay-multi-data:/data`、同 `--restart unless-stopped` 启动新容器；等 healthy 后验收 `/healthz=200`、POST 非 404、GET 404、日志不含密钥，任一失败自动回滚。
  > 不要用 `{{println .}}` + 按行读环境变量：`docker inspect --format` 会在输出末尾补一个换行，凭空多出一条空记录。
- **`client_secret` 注入方式**：部署者交互式 `read -rsp`（不回显、不进命令行历史、不生成 `oidc.env`），只存在于容器进程环境；也可改用 0600 的 `oidc.env` + `--env-file`。`docker restart` 不受影响，但**删除并重建容器会丢失配置**，需重新注入。
- **凭据正确性验证**：在容器内由 Node 从 `process.env` 读密钥，用无效授权码请求 IAM token 端点，返回 `400 invalid_grant`（而非 `invalid_client`），证明 client 认证通过、`client_secret` 正确；全过程不打印密钥、Basic 头或令牌。

| 复核项 | 结果 |
|---|---|
| 容器 | `dsh-relay-multi` = `0.8.0-oidc` Up healthy；备份 `dsh-relay-multi-pre-oidc` = `0.7.1` Exited(0) |
| OIDC 环境变量 | `DSH_IAM_OIDC_ISSUER` / `CLIENT_ID` / `CLIENT_SECRET` 三个键齐备（值不落文档、日志） |
| `POST /api/v1/auth/iam/oidc` | 18081 = 400，8443 = 400（切换前两者均 404 `METHOD_NOT_FOUND`） |
| `GET` 同路径 | 404 |
| `/healthz` | 18081 = 200，8443 = 200 |
| 中继日志 | 未发现 `client_secret` |
| 443 上 `dsh-relay-server-1` | Up healthy，不受影响 |

- 回滚：`ssh root@118.196.18.181 '/root/dsh-relay-multi/switch-to-oidc.sh rollback'`（回滚后 OIDC 会恢复 404，符合预期）。

## 10. 安全约束（硬约束）

- `client_secret` **绝不**进手机端、dart-define、代码库、文档、命令行历史或日志；只在服务端运行环境的环境变量中。
- 管理员密钥绝不落手机端，联调时也不临时塞进去。
- `redirect_uri` 必须与白名单逐字一致，不能附加额外 query。
- `state` / `nonce` 每次登录重新生成并校验；PKCE `code_verifier` 不出 App、只存进程内存，不落盘、不进日志。App 在登录期间被回收即作废本次登录（§8.2 第 8 项）。
- `client_id` 是公开标识，允许作为代码库默认值与 dart-define；这不改变对 `client_secret` 与管理员密钥的排除。
- 业务方不保存 IAM 令牌（`refresh_token_ttl=0`），中继只签发自己的账号会话。
