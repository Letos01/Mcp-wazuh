#!/usr/bin/env bash
# Creates the least-privilege accounts mcp-wazuh needs, in a LAB built with
# wazuh-docker single-node (default admin credentials below - change them in production).
#
#   ./scripts/lab-create-readonly-users.sh 'Str0ng!ReaderPass'
#
# 1. Wazuh Server API: user "mcp-reader" bound to the built-in "readonly" role (id 2).
# 2. Wazuh Indexer (OpenSearch security plugin): user "mcp-reader" with read-only
#    access to wazuh-alerts-* and wazuh-states-vulnerabilities-* only.
set -euo pipefail

READER_PASS="${1:?usage: $0 '<password: 8-64 chars with upper, lower, digit and symbol>'}"
API="${WAZUH_API_URL:-https://localhost:55000}"
API_ADMIN_USER="${WAZUH_API_ADMIN_USER:-wazuh-wui}"
API_ADMIN_PASS="${WAZUH_API_ADMIN_PASS:-MyS3cr37P450r.*-}"
IDX="${WAZUH_INDEXER_URL:-https://localhost:9200}"
IDX_ADMIN_USER="${WAZUH_INDEXER_ADMIN_USER:-admin}"
IDX_ADMIN_PASS="${WAZUH_INDEXER_ADMIN_PASS:-SecretPassword}"
CURL=(curl -sS -k --fail-with-body)   # -k: lab self-signed certificates

json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }
PASS_JSON=$(json_escape "$READER_PASS")

echo "==> Wazuh API: creating user mcp-reader"
TOKEN=$("${CURL[@]}" -u "$API_ADMIN_USER:$API_ADMIN_PASS" -X POST "$API/security/user/authenticate?raw=true")
AUTH=(-H "Authorization: Bearer $TOKEN")
"${CURL[@]}" "${AUTH[@]}" -H 'Content-Type: application/json' -X POST "$API/security/users" \
  -d "{\"username\":\"mcp-reader\",\"password\":$PASS_JSON}" >/dev/null || echo "   (user may already exist)"
USER_ID=$("${CURL[@]}" "${AUTH[@]}" "$API/security/users?search=mcp-reader" |
  python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]["affected_items"]; print(next(u["id"] for u in d if u["username"]=="mcp-reader"))')
echo "==> Wazuh API: binding user $USER_ID to role 'readonly' (id 2)"
"${CURL[@]}" "${AUTH[@]}" -X POST "$API/security/users/$USER_ID/roles?role_ids=2" >/dev/null

echo "==> Indexer: creating role mcp_reader (read-only on alerts + vulnerability state)"
IAUTH=(-u "$IDX_ADMIN_USER:$IDX_ADMIN_PASS" -H 'Content-Type: application/json')
"${CURL[@]}" "${IAUTH[@]}" -X PUT "$IDX/_plugins/_security/api/roles/mcp_reader" -d '{
  "cluster_permissions": ["cluster_composite_ops_ro"],
  "index_permissions": [{
    "index_patterns": ["wazuh-alerts-*", "wazuh-states-vulnerabilities-*"],
    "allowed_actions": ["read"]
  }]
}' >/dev/null
echo "==> Indexer: creating internal user mcp-reader"
"${CURL[@]}" "${IAUTH[@]}" -X PUT "$IDX/_plugins/_security/api/internalusers/mcp-reader" \
  -d "{\"password\":$PASS_JSON,\"backend_roles\":[]}" >/dev/null
"${CURL[@]}" "${IAUTH[@]}" -X PUT "$IDX/_plugins/_security/api/rolesmapping/mcp_reader" \
  -d '{"users":["mcp-reader"]}' >/dev/null

echo "Done. Use WAZUH_API_USER=mcp-reader and WAZUH_INDEXER_USER=mcp-reader in mcp-wazuh."
