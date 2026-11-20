# 发布 Runbook：如意账号登录（AIServer 桌面授权）

- 代码基线：`fix/web-login-oidc`（`5d0b1098` + `4b48a0b9` + 企业统一身份那个提交）
- 目标：让 `POST /api/v1/auth/aiserver/exchange` 上线，如意 App SSO 可完成注册
- 前置事实（2026-11-16 已核实）：生产已在使用统一账号派生 `iam:<sha256(issuer+subject)>`，升级不会改变设备归属
- 原则：本文只写变量名与步骤，**任何密钥、密码、令牌一律不落仓库**，真实值只在目标机 `unified.env`（600）

---

## 一、发布前检查（缺任一不要发）

### 1. AIserver 白名单必须逐字匹配

`desktop_redirect_whitelist` 表内需同时存在两组，且 `client_id` 与 `redirect_uri` 成对逐字一致：

| client_id | redirect_uri |
|---|---|
| `dsh-remote-web` | `https://<RELAY_HOST>:8443/app/callback` |
| `ruyi-android` | `ruyiai://auth3/callback` |

注意：生产现有 IAM 的 `client_id` 是 `dsh-remote-mobile`，与 AIserver 桌面授权用的 `dsh-remote-web` **不是同一个**，不要混用。

### 2. 环境变量需新增 6 项

相对当前生产 env，需补齐（取值见 `/root/dsh-relay-multi/unified.env`）：

```
DSH_IDENTITY_BASE               # 身份服务基址；沿用旧名 DSH_IAM_BASE 也能启动，但会打 deprecation 警告
DSH_AISERVER_BASE               # AIserver 部署根（含反代前缀，不带尾部斜杠）
DSH_AISERVER_CLIENT_ID
DSH_AISERVER_WEB_REDIRECT_URI
DSH_AISERVER_MOBILE_CLIENT_ID    # 可选组，但必须与下一行成对
DSH_AISERVER_MOBILE_REDIRECT_URI
```

**硬约束**：配了 `DSH_AISERVER_*` 却没有 `DSH_IDENTITY_BASE`（或旧名）与 `DSH_IAM_ISSUER`，服务**拒绝启动**。启动失败比短暂断连严重得多。

### 3. 状态快照与临时文件清理

见第二节加固清单第 1–2 条。

### 4. preflight 预检

```bash
/root/dsh-relay-multi/switch-to-unified.sh preflight
```

独立临时卷 + 18082 端口验证，不碰线上。起不来时回滚成本为零。

---

## 二、重启不丢状态：机制与加固清单

### 机制（代码已保证，无需改动）

| 保障 | 实现 | 位置 |
|---|---|---|
| 数据持久化 | `dsh-relay-multi-data` 卷 → `/data/state.json`（accounts / devices / tokens） | 容器挂载 |
| 原子写 | `state.json.tmp` 独占创建 → write → **fsync** → **rename** 原子替换 | `store.ts` `save()` |
| 启动校验 | `accountId == hash(account)`、设备与令牌归属链一致，坏数据拒绝启动 | `store.ts` 构造函数 |
| 升版备份 | v1→v2 生成 `state.json.v1.bak`，独占创建 + fsync，已存在不覆盖 | `store.ts` 构造函数 |
| 优雅关闭 | `SIGINT` / `SIGTERM` → `app.close()` | `main.ts` |

### 加固清单（发布前按序执行）

1. **快照**：
   ```bash
   docker exec dsh-relay-multi sh -c 'cp /data/state.json /data/state.json.bak-$(date +%Y%m%d%H%M)'
   ```
2. **清遗留临时文件**：`save()` 用 `openSync(tmp,'wx')` 独占创建，若上次被 SIGKILL 会遗留 `state.json.tmp`，导致下次启动 `EEXIST` 失败。
   ```bash
   docker exec dsh-relay-multi rm -f /data/state.json.tmp
   ```
3. **用 `docker stop`，禁用 `docker kill`**：SIGTERM 给 10s 宽限完成写盘。
4. **停服后确认** `state.json` 时间戳已更新，再替换容器。
5. **复用同一卷** `-v dsh-relay-multi-data:/data`，绝不换卷（换卷 = 账号与设备全丢）。

### 会丢的三类（设计如此，不影响注册）

| 状态 | 存储 | 重启后 |
|---|---|---|
| 网页账号会话 | 内存 `sessions` Map | 失效，需重登一次 |
| 未使用配对码 | 内存 `registrationCodes` Map | 作废，重新生成 |
| 在线状态 / WebSocket | 内存 `gateway.peers` | 由客户端重连恢复 |

---

## 三、发布步骤

```bash
# 1. 目标机构建镜像（构建上下文为仓库根）
docker build -f apps/server/Dockerfile -t dsh-relay-multi:<TAG> .

# 2. 改 switch-to-unified.sh 两处（旧备份名会 die）
#    NEW_IMAGE=dsh-relay-multi:<TAG>
#    BACKUP=dsh-relay-multi-<新备份名>

# 3. 预检 → 切流
/root/dsh-relay-multi/switch-to-unified.sh preflight
/root/dsh-relay-multi/switch-to-unified.sh switch
```

---

## 四、验收

1. `/healthz` 返回 200。
2. `POST /api/v1/auth/aiserver/exchange` 未认证/空 body 返回 **400**（不是 404）；`GET` 返回 404。
3. 日志无 `DSH_IAM_ISSUER` 缺失告警、无 `client_secret`。
4. 手机真机：SSO → 完成注册 → `listHosts` 能看到桌面 Host。
5. 网页管理台设备列表仍为 81 台（发布前基线），无异常减少。

---

## 五、回滚

```bash
/root/dsh-relay-multi/switch-to-unified.sh rollback
```

若 rollback 不可用，改 compose 的 image tag 回旧镜像再 `up`——`docker rename` 不改 label，不要依赖它保留副本。

---

## 六、本次发布对活动终端的影响（2026-11-16 核实）

| 维度 | 影响 |
|---|---|
| 设备 / 令牌（81 / 379） | 不丢，复用卷即保留 |
| 在线连接 | 短断连 15–40s，App 自动重连（3s 判死 / 6s 恢复 / follow 续传） |
| 网页会话 | 需重登一次 |
| 未使用配对码 | 作废，重新生成 |
