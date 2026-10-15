#!/usr/bin/env bash
# Stops the lab started by lab-up.sh. Add --purge to also delete Wazuh volumes and the cloned stack.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="${LAB_DIR:-$ROOT/.lab}"
cd "$LAB_DIR/wazuh-docker/single-node"
if [ "${1:-}" = "--purge" ]; then
  docker compose down -v
  chmod -R u+w "$LAB_DIR"   # the certs generator leaves its output directory read-only
  rm -rf "$LAB_DIR"
else
  docker compose down
fi
