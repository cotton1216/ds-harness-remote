#!/usr/bin/env bash
# 把线上中继切到「统一身份」镜像：AI-Server profile 与 OIDC id_token 共用同一账号键。
# 安全约束：环境变量经 NUL 导出后写入 0600 文件，再用 --env-file 注入；
# secret 不打印、不进命令行、不进脚本正文。
# 用法：
#   switch-to-unified.sh preflight   # 用临时卷在备用端口起一次，验证镜像可用，不碰线上
#   switch-to-unified.sh switch      # 预检通过后切换，失败自动回滚
#   switch-to-unified.sh rollback    # 手工回滚
set -euo pipefail

NAME=dsh-relay-multi
BACKUP=dsh-relay-multi-pre-unified2
NEW_IMAGE=dsh-relay-multi:0.9.1-unified-fallback
DIR=/root/dsh-relay-multi
ENVFILE=$DIR/unified.env
PROBE_PORT=18082

log() { printf '[unified] %s\n' "$*"; }
die() { printf '[unified][ERROR] %s\n' "$*" >&2; exit 1; }

dump_env() {
  [ -f "$ENVFILE" ] && return 0
  umask 077
  local fmt='{{range .Config.Env}}{{printf "%s\n" .}}{{end}}'
  # docker inspect 会在输出末尾再补一个换行；空行不是合法 KEY=VALUE，直接丢弃。
  docker inspect "$NAME" --format "$fmt" | sed '/^$/d' > "$ENVFILE"
  chmod 600 "$ENVFILE"
  local want seen
  want=$(docker inspect "$NAME" --format '{{len .Config.Env}}')
  seen=$(wc -l < "$ENVFILE" | tr -d ' ')
  [ "$want" = "$seen" ] || die "环境变量复现不完整：声明 $want，写入 $seen"
  log "已导出 $seen 条环境变量到 $ENVFILE（600）"
}

wait_health() {
  local port=$1 i
  for i in $(seq 1 40); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$port/healthz")" = 200 ]; then return 0; fi
    sleep 1
  done
  return 1
}

preflight() {
  dump_env
  docker rm -f "$NAME-preflight" >/dev/null 2>&1 || true
  rm -rf /tmp/relay-preflight && mkdir -p /tmp/relay-preflight
  # 镜像以 node(1000) 运行，/data 必须可写，否则启动即 EACCES（仅预检临时目录）。
  chown 1000:1000 /tmp/relay-preflight
  log '启动预检容器（独立临时卷，不接触线上数据）'
  docker run -d --name "$NAME-preflight" \
    --env-file "$ENVFILE" \
    -p 127.0.0.1:$PROBE_PORT:8080 \
    -v /tmp/relay-preflight:/data \
    --restart no \
    "$NEW_IMAGE" >/dev/null
  wait_health "$PROBE_PORT" || { docker logs --tail 30 "$NAME-preflight"; docker rm -f "$NAME-preflight" >/dev/null; die '预检：healthz 未通过'; }
  local oidc_post oidc_get
  oidc_post=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST "http://127.0.0.1:$PROBE_PORT/api/v1/auth/iam/oidc" -H 'content-type: application/json' -d '{}')
  oidc_get=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PROBE_PORT/api/v1/auth/iam/oidc")
  log "预检：healthz=200 POST oidc=$oidc_post GET oidc=$oidc_get"
  [ "$oidc_post" = 400 ] || { docker logs --tail 30 "$NAME-preflight"; die "预检失败：POST oidc 期望 400，实际 $oidc_post"; }
  [ "$oidc_get" = 404 ] || die "预检失败：GET oidc 期望 404，实际 $oidc_get"
  if docker logs "$NAME-preflight" 2>&1 | grep -q 'DSH_IAM_ISSUER'; then
    docker logs --tail 20 "$NAME-preflight"; die '预检失败：可信 issuer 缺失，启动即报错'
  fi
  log '预检通过，清理预检容器'
  docker rm -f "$NAME-preflight" >/dev/null 2>&1 || true
  rm -rf /tmp/relay-preflight
}

rollback() {
  log '回滚：删除新容器并恢复备份'
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if docker ps -a --format '{{.Names}}' | grep -qx "$BACKUP"; then
    docker rename "$BACKUP" "$NAME" || die "rename 失败，旧容器名为 $BACKUP"
    docker start "$NAME" >/dev/null || die '旧容器启动失败'
    wait_health 18081 || die '回滚后 healthz 未恢复，请人工介入'
    log '已回滚，healthz 恢复'
  else
    die "备份容器 $BACKUP 不存在，无法自动回滚"
  fi
}

case "${1:-switch}" in
  preflight) preflight; exit 0 ;;
  rollback) rollback; exit 0 ;;
  switch) ;;
  *) die "用法: $0 [preflight|switch|rollback]" ;;
esac

docker image inspect "$NEW_IMAGE" >/dev/null 2>&1 || die "镜像不存在: $NEW_IMAGE"
docker ps --format '{{.Names}}' | grep -qx "$NAME" || die "没有运行中的 $NAME"
docker ps -a --format '{{.Names}}' | grep -qx "$BACKUP" && die "备份名 $BACKUP 已存在，请先处理"
dump_env

log "切换 $NAME 到 $NEW_IMAGE"
docker stop "$NAME" >/dev/null
docker rename "$NAME" "$BACKUP" || { docker start "$NAME" >/dev/null; die '重命名旧容器失败'; }

start_new() {
  docker run -d --name "$NAME" \
    --env-file "$ENVFILE" \
    -p 127.0.0.1:18081:8080 \
    -v dsh-relay-multi-data:/data \
    --restart unless-stopped \
    "$NEW_IMAGE" >/dev/null
}

if ! start_new; then
  rollback
  die '新容器启动失败，已回滚'
fi
if ! wait_health 18081; then
  docker logs --tail 40 "$NAME"
  rollback
  die '新容器 healthz 未通过，已回滚'
fi

POST=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST http://127.0.0.1:18081/api/v1/auth/iam/oidc -H 'content-type: application/json' -d '{}')
GET=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:18081/api/v1/auth/iam/oidc)
log "验收：healthz=200 POST oidc=$POST GET oidc=$GET"
if [ "$POST" != 400 ] || [ "$GET" != 404 ]; then
  rollback
  die "验收失败（POST=$POST GET=$GET），已回滚"
fi
if docker logs "$NAME" 2>&1 | grep -qi 'client_secret'; then
  rollback
  die '日志出现 client_secret 字样，已回滚'
fi
log '切换完成。旧容器保留为'
log "  $BACKUP（回滚：$0 rollback）"
