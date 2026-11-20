#!/usr/bin/env bash
# 在服务器本机验证多账号部署：登录、注册、跨账号可见性。不打印密码。
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
BASE="https://${RELAY_HOST}:8443"
API=$BASE/api/v1
CURL=(curl -sS --resolve "${RELAY_HOST}:8443:127.0.0.1")
A=$(python3 -c "import json;print(json.load(open('/root/dsh-relay-multi/accounts.json'))[0]['account'])")
PA=$(python3 -c "import json;print(json.load(open('/root/dsh-relay-multi/accounts.json'))[0]['password'])")
B=$(python3 -c "import json;print(json.load(open('/root/dsh-relay-multi/accounts.json'))[1]['account'])")
PB=$(python3 -c "import json;print(json.load(open('/root/dsh-relay-multi/accounts.json'))[1]['password'])")

login() { "${CURL[@]}" -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$1\",\"password\":\"$2\"}"; }

TA=$(login "$A" "$PA" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
TB=$(login "$B" "$PB" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "登录 A($A): OK  登录 B($B): OK"

KEY=$(python3 -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')
DEV=$(python3 -c 'import uuid;print(uuid.uuid4())')
REG=$("${CURL[@]}" -X POST "$API/devices/register" -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' \
  -d "{\"v\":1,\"device\":{\"deviceId\":\"$DEV\",\"identityKey\":\"$KEY\",\"name\":\"acceptance-host\",\"role\":\"host\",\"platform\":\"linux\",\"clientVersion\":\"0.6.3\"}}")
echo "A 注册 Host: $(echo "$REG" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("OK" if d.get("accessToken") else d)')"

CA=$("${CURL[@]}" "$API/account/devices" -H "Authorization: Bearer $TA" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["items"]))')
CB=$("${CURL[@]}" "$API/account/devices" -H "Authorization: Bearer $TB" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["items"]))')
echo "A 可见设备数=$CA  B 可见设备数=$CB  (期望 1 和 0)"

X=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$API/devices/$DEV" -H "Authorization: Bearer $TB")
echo "B 查询 A 的设备 deviceId -> HTTP $X (期望 404)"

echo "=== 服务端日志（最近） ==="
docker logs --tail 6 dsh-relay-multi 2>&1 | tail -6
