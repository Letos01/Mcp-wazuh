# Lab: mcp-wazuh with a real Wazuh (single-node, Docker)

About 15 minutes on a machine with Docker and ~6 GB of free RAM.

## 1. Start Wazuh 4.14 (official wazuh-docker)

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.0
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
# wait ~1-2 min, then open https://localhost (admin / SecretPassword)
```

On Linux you may need `sudo sysctl -w vm.max_map_count=262144` for the indexer.

## 2. Create the read-only accounts

From the mcp-wazuh folder:

```bash
./scripts/lab-create-readonly-users.sh 'Str0ng!ReaderPass'
```

This creates `mcp-reader` on the Wazuh API with the built-in `readonly` role, and `mcp-reader` on the
Indexer with `read` on `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*` only.

## 3. Seed demo alerts (optional)

```bash
LAB_INSECURE=1 npm run seed:lab
```

This writes 11 sample alerts to today's `wazuh-alerts-4.x-*` index: SSH brute force, a web attack, encoded
PowerShell, an FIM change and a sudo event. Three of them carry prompt-injection payloads, so you can see the
defenses fire. The seeding uses the indexer **admin** account; mcp-wazuh never does.

## 4. Run mcp-wazuh

**Option A: Claude Desktop / Claude Code (stdio)**: see the README configuration, with:

```
WAZUH_API_URL=https://localhost:55000
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_API_USER=mcp-reader / WAZUH_INDEXER_USER=mcp-reader
TLS_INSECURE=true        # lab only: the API uses a self-signed certificate
```

**Option B: HTTP, in Docker, on the Wazuh network**:

```bash
cp .env.example .env     # set the mcp-reader passwords, MCP_AUTH_TOKENS, and:
# WAZUH_API_URL=https://wazuh.manager:55000
# WAZUH_INDEXER_URL=https://wazuh.indexer:9200
# TLS_INSECURE=true      (lab)
docker compose -f docker-compose.yml -f docker-compose.lab.yml up --build -d
curl -s localhost:8080/healthz
```

## 5. End-to-end tests against the lab

```bash
WAZUH_E2E=1 WAZUH_API_URL=https://localhost:55000 WAZUH_API_USER=mcp-reader WAZUH_API_PASSWORD='Str0ng!ReaderPass' \
WAZUH_INDEXER_URL=https://localhost:9200 WAZUH_INDEXER_USER=mcp-reader WAZUH_INDEXER_PASSWORD='Str0ng!ReaderPass' \
TLS_INSECURE=true npm run test:e2e
```

## 6. Try it

Ask Claude:

- "Which alerts of level 7 or higher happened in the last 24 hours?"
- "Which MITRE techniques appeared most today?"
- "Triage the FIM alert on db-01." (or use the `triage_alert` prompt)
- "Which agents are disconnected?"
- "List critical vulnerabilities on web-01."

Watch `audit/audit.jsonl` while you do it.
