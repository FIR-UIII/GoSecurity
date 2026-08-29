#!/usr/bin/env bash
#
# (Re)create the `xss-ato` realm in a Keycloak that is ALREADY running on
# http://127.0.0.1:8080 (e.g. the same container you use for ../s4-dirty-dance/).
#
# Use this instead of `docker compose up` when port 8080 is already taken.
# It is idempotent: it deletes the realm if present, imports it fresh from
# realm-export.json, and then FORCE-SETS the victim/attacker passwords via the
# admin API (importing plaintext credentials over REST is not always reliable -
# this is what the "Invalid username or password" symptom comes from).
#
#   bash keycloak/setup.sh
#
set -euo pipefail

KC="${KC:-http://127.0.0.1:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[*] getting admin token from $KC"
TOK=$(curl -sf -d client_id=admin-cli -d "username=$ADMIN_USER" -d "password=$ADMIN_PASS" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

echo "[*] deleting realm xss-ato if it exists"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOK" "$KC/admin/realms/xss-ato" || true

echo "[*] importing realm from realm-export.json"
curl -sf -o /dev/null -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  --data @"$HERE/realm-export.json" "$KC/admin/realms"

for U in victim attacker; do
  UID_=$(curl -sf -H "Authorization: Bearer $TOK" \
    "$KC/admin/realms/xss-ato/users?username=$U&exact=true" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
  curl -sf -o /dev/null -X PUT -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "{\"type\":\"password\",\"value\":\"$U\",\"temporary\":false}" \
    "$KC/admin/realms/xss-ato/users/$UID_/reset-password"
  echo "[*] password set: $U / $U"
done

echo "[+] realm xss-ato ready:"
echo "    users     victim / victim   and   attacker / attacker"
echo "    clients   s1-implicit  s2-confidential  s3-spa"
