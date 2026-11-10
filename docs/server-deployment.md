# 中继服务端部署手册

> 本文记录**线上实例的真实部署方式**，不是设计说明。设计见 [`server.md`](./server.md)，账号与 IAM 见 [`iam-oidc-integration.md`](./iam-oidc-integration.md)。
> 最后核对时间：2026-11-10，配置由 `docker inspect` / nginx 配置 / 部署脚本反查得出。

## 0. 这是怎么来的（背景）

仓库此前**没有任何服务端部署记录** —— `docs/` 下只有设计文档（`server.md`）和客户端安装文档（`installation.md`），`apps/server/Dockerfile` 存在但没有配套的部署说明。线上实例是靠 `/root/dsh-relay-multi/` 下的临时脚本运维的，那些文件从未进仓库。

本文把散落在服务器上的真实配置整理成可复原的文档。**再部署新实例时按本文操作即可，不需要重新摸索。**

## 1. 线上实例现状

| 项 | 值 |
|---|---|
| 对外地址 | `https://118.196.18.181:8443` |
| 主机 | `118.196.18.181`（hostname `VA`，SSH 别名 `xxtva`，root + `~/.ssh/id_ed25519`） |
| 容器名 | `dsh-relay-multi` |
| 镜像 | `dsh-relay-multi:0.9.1-unified-fallback`（本地构建，非 ghcr 官方镜像） |
| 容器监听 | `127.0.0.1:18081 -> 8080/tcp`（只绑回环，不直接对外） |
| 对外端口 | `8443` 由 nginx 提供 TLS 并反代到 18081 |
| 数据 | docker volume `dsh-relay-multi-data` → `/data/state.json`（owner `1000:1000`，权限 `600`） |
| 进程用户 | `node`（uid 1000）；`/data` 必须可写，否则启动即 `EACCES` |
| 重启策略 | `unless-stopped` |
| 网络 | `bridge` |

**为什么用 8443 而不是 443**：443 上跑着既有的单账号实例（`dsh-relay-server-1`，来自 `ghcr.io/liguobao/ds-harness-remote/server:latest`）。8443 是独立的多账号验收实例，两者完全隔离，不共享数据卷，也不改 `default_server`。

## 2. 拓扑

```
客户端 (Desktop / 手机)
   │  HTTPS 8443, WebSocket upgrade
   ▼
nginx  zz-dsh-remote-multi.conf
   │  listen 8443 ssl  (certbot IP 证书)
   │  proxy_pass http://127.0.0.1:18081
   ▼
dsh-relay-multi 容器 (node dist/main.js, uid 1000)
   │
   ▼
volume dsh-relay-multi-data → /data/state.json
```

## 3. 镜像构建

构建上下文只含服务端所需的最小子集（`package.json` / `pnpm-lock.yaml` / `pnpm-workspace.yaml` / `tsconfig.base.json` / `packages/protocol` / `apps/server`）。服务器上的 `/root/dsh-relay-build-unified/` 就是这个上下文，本地侧的等价物曾放在 `/tmp/relay-ctx/`，已打包为 `/tmp/relay-ctx.tgz`。

```bash
# 在构建上下文根目录执行
docker build -f apps/server/Dockerfile -t dsh-relay-multi:0.9.1-unified-fallback .
```

Dockerfile 要点（`apps/server/Dockerfile`）：

- 两阶段：`node:22-bookworm-slim` 分别做 build 和 runtime
- build 阶段用 `pnpm@9.15.4`，`--frozen-lockfile --ignore-scripts`
- 显式把**已编译**的 `packages/protocol` 拷进 `/out/node_modules`，避免依赖 deploy 快照里构建前的版本
- runtime 阶段 `chown node:node`，`chmod -R a+rX`，`USER node`
- 内建 `HEALTHCHECK` 打 `/healthz`，`CMD ["node", "dist/main.js"]`，`EXPOSE 8080`，`VOLUME ["/data"]`

**镜像 tag 语义**：`0.9.1-unified-fallback` 表示「统一身份派生 + 旧键回落」的那一版 —— 即 IAM 换票与 OIDC 登录共用 `iam:<sha256(issuer+subject)>`，拿不到 OIDC binding 时回落旧的 `iam:<数字id>`。换 tag 前先确认它对应哪次提交。

## 4. 容器启动

线上容器的等价启动命令（`--env-file` 见下节）：

```bash
docker run -d \
  --name dsh-relay-multi \
  --env-file /root/dsh-relay-multi/unified.env \
  -p 127.0.0.1:18081:8080 \
  -v dsh-relay-multi-data:/data \
  --restart unless-stopped \
  dsh-relay-multi:0.9.1-unified-fallback
```

注意两点：

- 端口**只绑 `127.0.0.1`**，对外暴露靠 nginx。不要改成 `0.0.0.0:8080` —— 那会绕过 TLS 直接暴露明文 HTTP。
- 卷挂的是命名卷 `dsh-relay-multi-data`。首次起容器前确认卷可写（`chown 1000:1000`），否则容器以 `node` 身份启动会立刻失败。

## 5. 环境变量

共 13 项（不含 `PATH` / `NODE_VERSION` / `YARN_VERSION` 这三个镜像自带项）。**值一律不进仓库**，线上存于 `/root/dsh-relay-multi/unified.env`（权限 `600`），由 `--env-file` 注入。可直接复制 [`../deploy/unified.env.example`](../deploy/unified.env.example) 起步。

| 变量 | 用途 |
|---|---|
| `DSH_SERVER_HOST` | 监听地址，容器内 `0.0.0.0` |
| `DSH_SERVER_PORT` | 容器内端口 `8080`（Dockerfile 已设默认） |
| `DSH_SERVER_PUBLIC_URL` | 对外基址，用于生成回调/注册码里的绝对链接 |
| `DSH_SERVER_DATA_FILE` | 数据文件路径 `/data/state.json` |
| `DSH_SERVER_LOG_LEVEL` | 日志级别 |
| `DSH_SERVER_ACCOUNTS_JSON` | 账号配置（内联 JSON），见 `/root/dsh-relay-multi/accounts.json` |
| `DSH_ALLOW_DEVICE_REBIND` | 允许设备换挂账号，多端联调时需要 `1` |
| `DSH_REGISTRATION_CODE_TTL_MS` | 授权码有效期 |
| `DSH_IAM_BASE` | IAM 服务基址 |
| `DSH_IAM_OIDC_ISSUER` | OIDC issuer；**显式设置时才会启用统一身份派生** |
| `DSH_IAM_OIDC_CLIENT_ID` | OIDC 客户端 ID |
| `DSH_IAM_OIDC_CLIENT_SECRET` | OIDC 客户端密钥 —— **唯一的高敏感项**，只存在于 `unified.env` |

> `DSH_IAM_OIDC_CLIENT_SECRET` 绝不写入文档、代码库、日志、命令行参数或聊天记录。需要新增实例时，由持有方在目标机上直接写入 `unified.env`（`umask 077` + `chmod 600`）。

## 6. nginx

文件：`/etc/nginx/sites-enabled/zz-dsh-remote-multi.conf`（软链自 `sites-available/`）

```nginx
server {
    listen 8443 ssl;
    server_name 118.196.18.181;

    ssl_certificate     /root/.certbot-ip/config/live/118.196.18.181/fullchain.pem;
    ssl_certificate_key /root/.certbot-ip/config/live/118.196.18.181/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:IPSSL:5m;
    ssl_session_timeout 1d;

    client_max_body_size 100m;

    location = /nginx-health { default_type text/plain; return 200 "ok"; }

    location / {
        proxy_pass http://127.0.0.1:18081;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $dsh_relay_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
```

**关键点**：

- `$dsh_relay_upgrade` 这个 map 定义在 `/etc/nginx/sites-available/dsh-remote-ip.conf` 顶部（`default upgrade; "" close;`）。改 8443 的配置时**不要删那个文件**，否则 nginx 启动会因变量未定义而失败。
- `proxy_read_timeout` / `proxy_send_timeout` 都是 `3600s`，`proxy_buffering off` —— 中继要维持长连接 WebSocket，用默认的 60s 会周期性掉线。
- 按 IP 访问时客户端不带 SNI，因此证书必须覆盖 IP（用 certbot 的 IP 证书，路径见上）。

```bash
nginx -t && systemctl reload nginx
```

## 7. TLS 证书

- 由 certbot 以 **IP 证书**方式签发，配置目录 `/root/.certbot-ip/`
- 续期后需要 `systemctl reload nginx`
- 证书过期会让所有客户端连不上（表现为 TLS 握手失败，不是 401）

## 8. 运维脚本（服务器侧，尚未进仓库）

`/root/dsh-relay-multi/` 下：

| 文件 | 作用 |
|---|---|
| `switch-to-unified.sh` | 切到统一身份镜像的完整流程：`preflight` / `switch` / `rollback` |
| `unified.env` | 环境变量（`600`），由 `--env-file` 注入 |
| `accounts.json` | `DSH_SERVER_ACCOUNTS_JSON` 的内容 |
| `verify-multi.sh` / `verify-multi2.sh` | 多账号验收脚本 |
| `switch-to-oidc.sh` | 切到 OIDC 登录的旧流程（已被 unified 取代） |

`switch-to-unified.sh` 的安全设计值得保留：

```bash
# 环境变量经 NUL 导出写入 0600 文件，再用 --env-file 注入
# secret 不打印、不进命令行、不进脚本正文
dump_env() {
  umask 077
  docker inspect "$NAME" --format '{{range .Config.Env}}{{printf "%s\n" .}}{{end}}' \
    | sed '/^$/d' > "$ENVFILE"
  chmod 600 "$ENVFILE"
  # 校验条数一致，避免漏导出
}
```

`preflight` 会用一个**独立临时卷**在备用端口（18082）起一次新镜像，等 `/healthz` 返回 200 且 `/api/v1/auth/iam/oidc` 分类正确后才允许 `switch`。这一步不能省 —— 镜像起不来时线上还没动，回滚成本为零。

## 9. 验证

```bash
# 健康检查（容器内自检）
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18081/healthz   # 期望 200

# 对外 TLS 与反代
curl -sk -o /dev/null -w '%{http_code}\n' https://118.196.18.181:8443/healthz

# nginx 自身健康
curl -sk https://118.196.18.181:8443/nginx-health    # 期望 ok

# OIDC 端点是否被中继识别（空 body 应返回分类错误，而不是 404）
curl -sk -X POST https://118.196.18.181:8443/api/v1/auth/iam/oidc \
  -H 'content-type: application/json' -d '{}'
```

`/healthz` 通但客户端仍连不上时，按序查：nginx 配置有没有 reload → 证书是否过期 → 容器日志 `docker logs --tail 50 dsh-relay-multi`。

## 10. 回滚

`switch-to-unified.sh` 会先备份旧容器为 `dsh-relay-multi-pre-unified2`，切换失败自动回滚。手工回滚：

```bash
docker rm -f dsh-relay-multi
docker rename dsh-relay-multi-pre-unified2 dsh-relay-multi
docker start dsh-relay-multi
```

数据在命名卷里，容器重建不影响账号与设备记录。要改回旧镜像只需把 `-d` 的镜像 tag 换掉重跑。

## 11. 已知坑

| 现象 | 原因 | 处理 |
|---|---|---|
| 容器启动即退出，日志 `EACCES /data` | `/data` 属主不是 1000 | `chown 1000:1000` 卷目录或临时目录 |
| nginx 启动失败，报变量未定义 | 删了 `dsh-remote-ip.conf` 里的 map | 保留该文件，或把 map 复制到 8443 的配置里 |
| WebSocket 每小时断一次 | 超时用了默认 60s | `proxy_read_timeout 3600s` + `proxy_buffering off` |
| 客户端 TLS 握手失败 | IP 证书过期 | certbot 续期后 reload nginx |
| 换票返回「中继尚未配置 IAM 单点登录」 | 容器没注入 `DSH_IAM_*` 三项 | 检查 `unified.env`，重启容器 |
| 同一台 Host 出现多条记录 | `register()` 只按 `deviceId` 查重，重装后 `deviceId` 变新 | 见 `server.md` 设备注册一节；清理需按 `identityKey` 合并 |
| 多端账号分裂 | 旧路径用 `iam:<数字id>`，OIDC 用 `iam:<sub>` | 需要 `DSH_IAM_OIDC_ISSUER` 显式设置才走统一派生 |

## 12. 待补

- [x] 把 `/root/dsh-relay-multi/` 下的运维脚本收进仓库 —— 已收进 [`../deploy/relay/`](../deploy/relay/)，密钥与账号全部替换为占位符
- [x] nginx 配置纳入版本管理 —— 已收进 [`../deploy/nginx/`](../deploy/nginx/)，含 `dsh-remote-ip.conf` 的 map 定义；主机地址改为 `<RELAY_IP>` 占位符
- [ ] 443 上既有单账号实例的部署方式仍未落档（`deploy/nginx/dsh-remote-ip.conf` 只覆盖了它的 nginx 层）
- [ ] 证书续期的自动化与监控（当前依赖人工 `systemctl reload nginx`）
- [ ] 镜像构建尚未脚本化：`docker build -t <tag>` 的 tag 语义靠人工约定，没有 CI 产出
