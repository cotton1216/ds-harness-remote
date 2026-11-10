# 部署资产

线上中继实例（`https://<RELAY_IP>:8443`）的部署脚本与配置。完整说明见 [`../docs/server-deployment.md`](../docs/server-deployment.md)，本目录只是**可直接使用的文件**。

## 为什么会有这个目录

这些文件此前只存在于服务器 `/root/dsh-relay-multi/`，从未进仓库。仓库里只有 `apps/server/Dockerfile` 和一个设计文档 `docs/server.md`，重建实例时没有任何可照抄的东西。2026-11-10 从线上反查后收进来（提交 `b860d596` 的文档 + 本次的文件）。

## 目录结构

```
deploy/
├── relay/
│   ├── switch-to-unified.sh       镜像切换：preflight 预检 → switch → 失败自动回滚
│   ├── verify-multi.sh            多账号验证：登录 / 注册 / 跨账号可见性
│   ├── verify-multi2.sh           多账号验证（第二组场景）
│   ├── accounts.json.example      账号表模板（复制为 accounts.json 后填真实密码）
│   └── legacy/
│       └── switch-to-oidc.sh      旧的 OIDC 切换流程，已被 unified 取代，仅存档
├── nginx/
│   ├── zz-dsh-remote-multi.conf   8443 站点：TLS + 反代到 127.0.0.1:18081
│   └── dsh-remote-ip.conf         443 站点（另一实例）+ **$dsh_relay_upgrade 的 map 定义**
└── unified.env.example            环境变量模板（14 项，密钥留空）
```

## 先替换占位符

仓库里的配置是**不指向任何具体实例的模板** —— 主机地址与 IAM issuer 都写成了 `<RELAY_IP>` / `<IAM_ISSUER>`。部署前按本机真实值替换：

```bash
sed -i 's/<RELAY_IP>/你的公网IP/g'        deploy/nginx/*.conf
sed -i 's/<IAM_ISSUER>/你的issuer/g'     deploy/relay/legacy/switch-to-oidc.sh
```

`unified.env.example` 与 `accounts.json.example` 里的占位符在复制成真实文件时**手工填**，不要用 sed 批处理 —— 密钥走批量替换容易留在 shell 历史里。

## 部署顺序

```bash
# 1. 目标机上准备目录
mkdir -p /root/dsh-relay-multi

# 2. 账号表与环境变量（密钥手填，不要走 scp 之外的通道）
cp deploy/relay/accounts.json.example /root/dsh-relay-multi/accounts.json
cp deploy/unified.env.example      /root/dsh-relay-multi/unified.env
# 编辑两个文件填真实值
chmod 600 /root/dsh-relay-multi/unified.env

# 3. 放脚本
cp deploy/relay/*.sh /root/dsh-relay-multi/
chmod +x /root/dsh-relay-multi/*.sh

# 4. 构建镜像（构建上下文只需服务端子集）
docker build -f apps/server/Dockerfile -t dsh-relay-multi:<TAG> .

# 5. 起容器
docker run -d \
  --name dsh-relay-multi \
  --env-file /root/dsh-relay-multi/unified.env \
  -p 127.0.0.1:18081:8080 \
  -v dsh-relay-multi-data:/data \
  --restart unless-stopped \
  dsh-relay-multi:<TAG>

# 6. nginx
cp deploy/nginx/zz-dsh-remote-multi.conf /etc/nginx/sites-enabled/
# dsh-remote-ip.conf 提供 map，443 实例也在用它 —— 已有则不要覆盖
nginx -t && systemctl reload nginx

# 7. 验证
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18081/healthz      # 200
curl -sk -o /dev/null -w '%{http_code}\n' https://<RELAY_HOST>:8443/healthz # 200
```

## 升级镜像

```bash
/root/dsh-relay-multi/switch-to-unified.sh preflight   # 独立临时卷 + 18082 端口验证，不碰线上
/root/dsh-relay-multi/switch-to-unified.sh switch      # 切线上，失败自动回滚
/root/dsh-relay-multi/switch-to-unified.sh rollback    # 手工回滚
```

`preflight` 会等 `/healthz` 返回 200、确认 `POST /api/v1/auth/iam/oidc` 返回 400 而 `GET` 返回 404，并检查日志里没有 `DSH_IAM_ISSUER` 缺失告警。**这一步不能省** —— 镜像起不来时线上还没动，回滚成本为零。

## 三个必须注意的点

**1. 脚本里的路径是硬编码的**

`switch-to-unified.sh` 顶部：

```bash
NAME=dsh-relay-multi
BACKUP=dsh-relay-multi-pre-unified2
DIR=/root/dsh-relay-multi
ENVFILE=$DIR/unified.env
```

部署到别的机器时要么保持 `/root/dsh-relay-multi/`，要么改这几个变量。别指望它自动探测。

**2. `$dsh_relay_upgrade` 的 map 不在 8443 的配置文件里**

它定义在 `nginx/dsh-remote-ip.conf` 顶部：

```nginx
map $http_upgrade $dsh_relay_upgrade {
    default upgrade;
    ""      close;
}
```

8443 的 `proxy_set_header Connection $dsh_relay_upgrade;` 依赖它。**删掉 `dsh-remote-ip.conf` 会让 nginx 因变量未定义而启动失败**。如果新机器上不打算跑 443 实例，至少要把这两行 map 复制到某个被 `http {}` include 的文件里。

**3. 密钥绝不进仓库**

`unified.env.example` 和 `accounts.json.example` 里全是占位符。真实值只写在目标机的 `unified.env`（`600`）里。

`switch-to-unified.sh` 切换时会把日志里出现 `client_secret` 视为失败并自动回滚 —— 这条检查不要删。

## 验证脚本的前置条件

`verify-multi.sh` / `verify-multi2.sh` 从 `/root/dsh-relay-multi/accounts.json` 读取两个账号（`[0]` 和 `[1]`）做跨账号可见性测试。所以：

- 账号表至少要有 2 条
- 脚本必须在**服务器本机**跑（`BASE=https://127.0.0.1:8443`，用 `-k` 忽略 IP 证书校验）
