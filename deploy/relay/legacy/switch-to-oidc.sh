#!/usr/bin/env bash
# 把线上中继从 0.7.1 切换到 0.8.0-oidc，并注入 IAM OIDC 配置。
# 安全约束：client_secret 不打印、不落脚本、不进命令行历史；只在容器进程环境里。
# 用法：
#   ssh    root@<RELAY_IP> '/root/dsh-relay-multi/switch-to-oidc.sh check'    # 免密钥自检
#   ssh -t root@<RELAY_IP> '/root/dsh-relay-multi/switch-to-oidc.sh'          # 交互输入 secret
#   ssh    root@<RELAY_IP> '/root/dsh-relay-multi/switch-to-oidc.sh rollback' # 回滚
set -euo pipefail

NAME=dsh-relay-multi
BACKUP=dsh-relay-multi-pre-oidc
NEW_IMAGE=dsh-relay-multi:0.8.0-oidc
OIDC_ENV=/root/dsh-relay-multi/oidc.env
ISSUER_DEFAULT="<IAM_ISSUER>"
CLIENT_ID_DEFAULT=dsh-remote-mobile
PROBE_URL=http://127.0.0.1:18081/api/v1/auth/iam/oidc

log() { printf '[switch] %s\n' "$*"; }
die() { printf '[switch][ERROR] %s\n' "$*" >&2; exit 1; }

rollback() {
  log '回滚到切换前容器…'
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if docker ps -a --format '{{.Names}}' | grep -qx "$BACKUP"; then
    docker rename "$BACKUP" "$NAME" >/dev/null \
      || die "改名失败，旧容器现名为 $BACKUP，请手工 rename + start"
    docker start "$NAME" >/dev/null || die '旧容器启动失败'
    log '已回滚并启动旧容器'
  else
    die "备份容器 $BACKUP 不存在，无法自动回滚"
  fi
}

# 用 NUL 分隔输出 env：某些值（多账号 JSON）本身含换行，按行读会被拆断。
# 只用 Docker 自带 Go template，不依赖 python3 / jq；末尾 docker 追加的换行不构成一条记录。
ENV_DUMP_FMT='{{range .Config.Env}}{{printf "%s\x00" .}}{{end}}'

case "${1:-switch}" in
  rollback) rollback; exit 0 ;;
  check)
    expected=$(docker inspect "$NAME" --format '{{len .Config.Env}}')
    seen=0; multiline=0
    while IFS= read -r -d '' e; do
      seen=$((seen+1))
      case "$e" in *$'\n'*) multiline=$((multiline+1)) ;; esac
    done < <(docker inspect "$NAME" --format "$ENV_DUMP_FMT")
    printf '[check] 声明 %s 条，完整解析 %s 条，其中含换行 %s 条\n' "$expected" "$seen" "$multiline"
    [ "$seen" -eq "$expected" ] || die 'check 不通过：环境变量无法完整复现'
    echo '[check] OK：可原样复现全部环境变量，线上未做任何变更'
    exit 0 ;;
  switch) ;;
  *) die "用法: $0 [switch|rollback|check]" ;;
esac

docker image inspect "$NEW_IMAGE" >/dev/null 2>&1 || die "镜像不存在: $NEW_IMAGE"
docker ps --format '{{.Names}}' | grep -qx "$NAME" || die "没有运行中的 $NAME，请先 rollback 或手工检查"
if docker ps -a --format '{{.Names}}' | grep -qx "$BACKUP"; then
  die "备份名 $BACKUP 已被占用（可能上次已切换成功）；如需重切请先手工处理"
fi

# ---- OIDC 配置：唯一接触 secret 的地方 ----
OIDC_ARGS=()
SECRET_FOR_LOGCHECK=''
if [ -f "$OIDC_ENV" ]; then
  mode=$(stat -c %a "$OIDC_ENV")
  [ "$mode" = 600 ] || die "$OIDC_ENV 权限应为 600，当前 $mode"
  for k in DSH_IAM_OIDC_ISSUER DSH_IAM_OIDC_CLIENT_ID DSH_IAM_OIDC_CLIENT_SECRET; do
    cut -d= -f1 "$OIDC_ENV" | grep -qx "$k" \
      || die "$OIDC_ENV 缺少键 $k（只校验键名，不回显值）"
  done
  log "使用 $OIDC_ENV（--env-file，值不进入命令行）"
  OIDC_ARGS+=(--env-file "$OIDC_ENV")
  SECRET_FOR_LOGCHECK=$(grep '^DSH_IAM_OIDC_CLIENT_SECRET=' "$OIDC_ENV" | head -1 | cut -d= -f2-)
else
  [ -t 0 ] || die "缺少 $OIDC_ENV 且当前非交互终端，无法安全获取 client_secret"
  read -rsp 'client_secret（输入不回显）: ' s
  printf '\n'
  [ -n "$s" ] || die 'client_secret 为空'
  OIDC_ARGS+=(
    -e "DSH_IAM_OIDC_ISSUER=$ISSUER_DEFAULT"
    -e "DSH_IAM_OIDC_CLIENT_ID=$CLIENT_ID_DEFAULT"
    -e "DSH_IAM_OIDC_CLIENT_SECRET=$s"
  )
  SECRET_FOR_LOGCHECK=$s
  unset s
fi

# ---- 继承现有容器全部环境变量（含账号配置，值不打印） ----
expected=$(docker inspect "$NAME" --format '{{len .Config.Env}}')
ENV_ARGS=()
seen=0
while IFS= read -r -d '' e; do
  seen=$((seen+1))
  [ -z "$e" ] && continue
  case "$e" in DSH_IAM_OIDC_*) continue ;; esac
  ENV_ARGS+=(-e "$e")
done < <(docker inspect "$NAME" --format "$ENV_DUMP_FMT")
[ "$seen" -eq "$expected" ] \
  || die "读取现有 env 异常（应为 $expected 条，实得 $seen 条），停止切换；线上未做任何变更"
log "继承现有环境变量 ${#ENV_ARGS[@]} 个（含换行的值已原样保留，值不打印）"

# ---- 切换：旧容器停掉但保留，便于回滚 ----
log "停止旧容器并保留为 $BACKUP"
docker stop "$NAME" >/dev/null
docker rename "$NAME" "$BACKUP" >/dev/null

if ! docker run -d --name "$NAME" \
      --restart unless-stopped \
      --user node \
      -p 127.0.0.1:18081:8080 \
      -v dsh-relay-multi-data:/data \
      "${ENV_ARGS[@]}" "${OIDC_ARGS[@]}" \
      "$NEW_IMAGE" >/dev/null; then
  printf '[switch][ERROR] 新容器启动失败\n' >&2
  rollback
  exit 1
fi
log "新容器已启动: $(docker inspect "$NAME" --format '{{.Id}}' | cut -c1-12)  $NEW_IMAGE"

# ---- 等待 healthy ----
h=starting
ok=0
for _ in $(seq 1 35); do
  h=$(docker inspect "$NAME" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}')
  [ "$h" = healthy ] && { ok=1; break; }
  [ "$h" = unhealthy ] && break
  sleep 2
done
if [ "$ok" != 1 ]; then
  printf '[switch][ERROR] 新容器未进入 healthy（最后状态: %s）\n' "$h" >&2
  docker logs --tail 40 "$NAME" 2>&1 | tail -40 >&2 || true
  rollback
  exit 1
fi
log '健康检查: healthy'

# ---- 验收 ----
health=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/healthz)
post=$(curl -s --noproxy '*' -o /tmp/dsh-oidc-probe.json -w '%{http_code}' \
        -X POST "$PROBE_URL" -H 'Content-Type: application/json' -d '{}')
get=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "$PROBE_URL")
rm -f /tmp/dsh-oidc-probe.json
log "验收: GET /healthz=$health  POST /auth/iam/oidc=$post  GET /auth/iam/oidc=$get"
if [ "$health" != 200 ] || [ "$post" = 404 ] || [ "$get" = 200 ]; then
  printf '[switch][ERROR] 验收不通过，自动回滚\n' >&2
  rollback
  exit 1
fi

# ---- 日志不得出现 client_secret（shell 内建比较，不进命令行） ----
if [ -n "$SECRET_FOR_LOGCHECK" ]; then
  logs=$(docker logs "$NAME" 2>&1 || true)
  case "$logs" in
    *"$SECRET_FOR_LOGCHECK"*)
      printf '[switch][ERROR] 容器日志中出现 client_secret，自动回滚\n' >&2
      rollback
      exit 1 ;;
  esac
  unset logs
fi
unset SECRET_FOR_LOGCHECK
log '日志检查: 未发现 client_secret'

log '切换完成 ✅'
log "备份容器（已停止）: $BACKUP  镜像 $(docker inspect "$BACKUP" --format '{{.Config.Image}}')"
log "回滚命令: $0 rollback"
