#!/usr/bin/env bash
# 用正确的设备令牌验证跨账号不可见/不可查。不打印密码。
set -euo pipefail
# 证书是给公网 host 签发的；用 --resolve 把该 host 指向回环，从而在校验 TLS
# 的前提下访问本机服务。禁用 -k，避免口令被中间人截获。fail-closed：读不到
# 权威 host 时直接退出，绝不回退到跳过校验。
ENV_FILE=/root/dsh-relay-multi/unified.env
PUBLIC_URL=$(sed -n 's/^DSH_SERVER_PUBLIC_URL=//p' "$ENV_FILE" 2>/dev/null | head -1)
if [ -z "$PUBLIC_URL" ]; then
  echo "无法从 $ENV_FILE 读取 DSH_SERVER_PUBLIC_URL" >&2; exit 1
fi
RELAY_HOST=$(printf '%s' "$PUBLIC_URL" | sed -E 's#^https?://([^/:]+).*#\1#')
if [ -z "$RELAY_HOST" ]; then
  echo "无法从 DSH_SERVER_PUBLIC_URL 解析主机名" >&2; exit 1
fi
API="https://${RELAY_HOST}:8443/api/v1"
CURL=(curl -sS --resolve "${RELAY_HOST}:8443:127.0.0.1")
read_acc() { python3 -c "import json;d=json.load(open('/root/dsh-relay-multi/accounts.json'));print(d[$1]['account'],d[$1]['password'])"; }
read -r A PA <<<"$(read_acc 0)"
read -r B PB <<<"$(read_acc 1)"
login() { "${CURL[@]}" -X POST "$API/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$1\",\"password\":\"$2\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])'; }
reg() { # $1 account-token  $2 role -> "accessToken deviceId"
  local key dev resp tok
  key=$(python3 -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')
  dev=$(python3 -c 'import uuid;print(uuid.uuid4())')
  resp=$("${CURL[@]}" -X POST "$API/devices/register" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d "{\"v\":1,\"device\":{\"deviceId\":\"$dev\",\"identityKey\":\"$key\",\"name\":\"accept-$2\",\"role\":\"$2\",\"platform\":\"linux\",\"clientVersion\":\"0.6.3\"}}")
  tok=$(echo "$resp" | python3 -c 'import sys,json;print(json.load(sys.stdin)["accessToken"])')
  echo "$tok $dev"
}
TA=$(login "$A" "$PA"); TB=$(login "$B" "$PB")
read -r AHOST A_HOST_ID <<<"$(reg "$TA" host)"
read -r BCLIENT B_CLIENT_ID <<<"$(reg "$TB" client)"
read -r ACLIENT _ <<<"$(reg "$TA" client)"

nA=$("${CURL[@]}" "$API/devices" -H "Authorization: Bearer $ACLIENT" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["items"]))')
nB=$("${CURL[@]}" "$API/devices" -H "Authorization: Bearer $BCLIENT" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["items"]))')
echo "A 的 client 看到 Host 数=$nA (期望 1)   B 的 client 看到 Host 数=$nB (期望 0)"

code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$API/devices/$A_HOST_ID" -H "Authorization: Bearer $BCLIENT")
echo "B 的 client 查 A 的 Host -> HTTP $code (期望 404)"
code2=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$API/devices/$A_HOST_ID/presence" -H "Authorization: Bearer $BCLIENT")
echo "B 的 client 查 A 的 Host 在线状态 -> HTTP $code2 (期望 404)"
code3=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$API/devices/$B_CLIENT_ID/name" -X POST -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' -d '{"name":"x"}')
echo "A 重命名 B 的设备 -> HTTP $code3 (期望 404)"
echo "$A_HOST_ID" > /root/dsh-relay-multi/.a-host-id
