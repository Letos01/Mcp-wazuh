#!/usr/bin/env bash
# One-shot LAB: real Wazuh 4.14 (single-node, Docker) + read-only users + sample alerts
# + mcp-wazuh end-to-end tests against it.
#
#   ./scripts/lab-up.sh            # needs Docker (Desktop) with ~6 GB RAM free, git, node 20+, curl
#   ./scripts/lab-down.sh          # stop and remove the lab
#
# Lab only: default Wazuh credentials and TLS_INSECURE=true (self-signed certificates).
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-v4.14.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="${LAB_DIR:-$ROOT/.lab}"
READER_PASS="${READER_PASS:-Str0ng!ReaderPass}"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }
need docker; need git; need node; need npm; need curl
docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker Desktop and try again."; exit 1; }

step "1/6 Wazuh $WAZUH_VERSION (wazuh-docker single-node)"
mkdir -p "$LAB_DIR"
if [ ! -d "$LAB_DIR/wazuh-docker" ]; then
  git clone -q --depth 1 --branch "$WAZUH_VERSION" https://github.com/wazuh/wazuh-docker.git "$LAB_DIR/wazuh-docker"
fi
cd "$LAB_DIR/wazuh-docker/single-node"
if [ ! -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
  docker compose -f generate-indexer-certs.yml run --rm generator
fi
# wazuh-docker 4.14's compose mounts root-ca-manager.pem for the manager, but
# wazuh-certs-generator:0.0.2 only writes root-ca.pem: same CA, extra copy.
CERTS=config/wazuh_indexer_ssl_certs
if [ ! -f "$CERTS/root-ca-manager.pem" ]; then
  chmod u+w "$CERTS"                                   # the generator leaves the directory read-only
  cp "$CERTS/root-ca.pem" "$CERTS/root-ca-manager.pem"
  chmod 444 "$CERTS/root-ca-manager.pem"
  chmod u-w "$CERTS"
fi
if [ "$(uname -s)" = "Linux" ] && [ "$(sysctl -n vm.max_map_count)" -lt 262144 ]; then
  echo "Linux: raising vm.max_map_count for the indexer (sudo)"; sudo sysctl -w vm.max_map_count=262144
fi
docker compose up -d

step "2/6 Waiting for the Indexer and the Wazuh API (can take 2-4 minutes)"
for i in $(seq 1 90); do
  idx=$(curl -sk -o /dev/null -w '%{http_code}' -u admin:SecretPassword https://localhost:9200/_cluster/health || true)
  api=$(curl -sk -o /dev/null -w '%{http_code}' -u 'wazuh-wui:MyS3cr37P450r.*-' -X POST \
        'https://localhost:55000/security/user/authenticate?raw=true' || true)
  printf '\r   indexer=%s api=%s (%ss)' "$idx" "$api" "$((i * 5))"
  [ "$idx" = 200 ] && [ "$api" = 200 ] && break
  sleep 5
  [ "$i" = 90 ] && { echo; echo "Timeout. Check: docker compose -f $LAB_DIR/wazuh-docker/single-node/docker-compose.yml logs"; exit 1; }
done
# the alerts index template is installed by the manager's filebeat; give it a moment
for i in $(seq 1 30); do
  curl -sk -u admin:SecretPassword https://localhost:9200/_index_template/wazuh -o /dev/null -w '%{http_code}' | grep -q 200 && break
  curl -sk -u admin:SecretPassword https://localhost:9200/_template/wazuh -o /dev/null -w '%{http_code}' | grep -q 200 && break
  sleep 5
done
# A cold manager needs more than the API's internal 10s budget to compile the
# ruleset, so the first GET /rules answers 500. Warm it up before the tests.
TOKEN=$(curl -sk -u 'wazuh-wui:MyS3cr37P450r.*-' -X POST \
        'https://localhost:55000/security/user/authenticate?raw=true')
for i in $(seq 1 12); do
  rules=$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
          'https://localhost:55000/rules?limit=1' || true)
  printf '\r   ruleset=%s' "$rules"
  [ "$rules" = 200 ] && break
  sleep 10
done
echo

cd "$ROOT"
step "3/6 Building mcp-wazuh"
npm ci --silent
npm run build --silent

step "4/6 Creating least-privilege users (mcp-reader)"
./scripts/lab-create-readonly-users.sh "$READER_PASS"

step "5/6 Seeding sample alerts (including prompt-injection payloads)"
LAB_INDEXER_URL=https://localhost:9200 LAB_INSECURE=1 node scripts/seed-lab-alerts.mjs

step "6/6 End-to-end tests against the live Wazuh"
export WAZUH_API_URL=https://localhost:55000 WAZUH_API_USER=mcp-reader WAZUH_API_PASSWORD="$READER_PASS"
export WAZUH_INDEXER_URL=https://localhost:9200 WAZUH_INDEXER_USER=mcp-reader WAZUH_INDEXER_PASSWORD="$READER_PASS"
export TLS_INSECURE=true
WAZUH_E2E=1 npm run test:e2e

cat <<EOF

Lab is up. Wazuh dashboard: https://localhost  (admin / SecretPassword)

Use it from Claude Desktop (claude_desktop_config.json -> mcpServers):
  "wazuh-lab": {
    "command": "node",
    "args": ["$ROOT/dist/index.js"],
    "env": {
      "WAZUH_API_URL": "https://localhost:55000", "WAZUH_API_USER": "mcp-reader", "WAZUH_API_PASSWORD": "$READER_PASS",
      "WAZUH_INDEXER_URL": "https://localhost:9200", "WAZUH_INDEXER_USER": "mcp-reader", "WAZUH_INDEXER_PASSWORD": "$READER_PASS",
      "TLS_INSECURE": "true", "AUDIT_LOG_PATH": "$ROOT/audit/audit.jsonl"
    }
  }

Or from Claude Code:
  claude mcp add wazuh-lab -e WAZUH_API_URL=https://localhost:55000 -e WAZUH_API_USER=mcp-reader \\
    -e WAZUH_API_PASSWORD='$READER_PASS' -e WAZUH_INDEXER_URL=https://localhost:9200 -e WAZUH_INDEXER_USER=mcp-reader \\
    -e WAZUH_INDEXER_PASSWORD='$READER_PASS' -e TLS_INSECURE=true -- node "$ROOT/dist/index.js"
EOF
