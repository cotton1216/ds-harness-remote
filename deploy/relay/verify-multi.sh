#!/usr/bin/env bash
# 在服务器本机验证多账号部署：登录、注册、跨账号可见性。不打印密码。
set -euo pipefail
BASE=https://127.0.0.1:8443
API=$BASE/api/v1
A=$(python3 -c "import json;print(json.load(open('/root/dsh-relay-multi/accounts.json'))[0]['account'])")
PA=$(python3 -c "import json;print(json.load(open('/root/dsh-relay-multi/accounts.json'))[0]['password'])")
B=$(python3 -c "import json;print(json.load(open('/root/dsh-relay-multi/accounts.json'))[1]['account'])")
PB=$(python3 -c "import json;print(json.load(open('/root/dsh-relay-multi/accounts.json'))[1]['password'])")

login() { curl -sk -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$1\",\"password\":\"$2\"}"; }

TA=$(login "$A" "$PA" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
TB=$(login "$B" "$PB" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "登录 A($A): OK  登录 B($B): OK"

KEY=$(python3 -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')
DEV=$(python3 -c 'import uuid;print(uuid.uuid4())')
REG=$(curl -sk -X POST "$API/devices/register" -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' \
  -d "{\"v\":1,\"device\":{\"deviceId\":\"$DEV\",\"identityKey\":\"$KEY\",\"name\":\"acceptance-host\",\"role\":\"host\",\"platform\":\"linux\",\"clientVersion\":\"0.6.3\"}}")
echo "A 注册 Host: $(echo "$REG" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("OK" if d.get("accessToken") else d)')"

CA=$(curl -sk "$API/account/devices" -H "Authorization: Bearer $TA" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["items"]))')
CB=$(curl -sk "$API/account/devices" -H "Authorization: Bearer $TB" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["items"]))')
echo "A 可见设备数=$CA  B 可见设备数=$CB  (期望 1 和 0)"

X=$(curl -sk -o /dev/null -w '%{http_code}' "$API/devices/$DEV" -H "Authorization: Bearer $TB")
echo "B 查询 A 的设备 deviceId -> HTTP $X (期望 404)"

echo "=== 服务端日志（最近） ==="
docker logs --tail 6 dsh-relay-multi 2>&1 | tail -6
