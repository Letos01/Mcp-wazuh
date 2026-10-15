# Lab: mcp-wazuh with a real Wazuh (single-node, Docker)

About 15 minutes on a machine with Docker and ~6 GB of free RAM.

## Shortcut: one command

```bash
./scripts/lab-up.sh        # Wazuh up -> read-only users -> sample alerts -> e2e tests
./scripts/lab-down.sh      # stop (add --purge to delete volumes)
```

The steps below are what the script does, for when you want to run them by hand.

## 1. Start Wazuh 4.14 (official wazuh-docker)

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.0
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
# The compose file mounts root-ca-manager.pem, which the 0.0.2 generator does not write:
# without this copy the manager container fails to start.
chmod u+w config/wazuh_indexer_ssl_certs
cp config/wazuh_indexer_ssl_certs/root-ca{,-manager}.pem
chmod 444 config/wazuh_indexer_ssl_certs/root-ca-manager.pem
chmod u-w config/wazuh_indexer_ssl_certs
docker compose up -d
# wait ~1-2 min, then open https://localhost (admin / SecretPassword)
```

A cold manager also needs a minute before `GET /rules` answers: the first call has to compile the
ruleset and the Wazuh API gives up at 10s, returning 500. `lab-up.sh` waits for it.

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

A live manager is not a quiet lab: it runs its own SCA (Security Configuration Assessment) scan and
writes a few hundred alerts of its own (rule 19007-19009, level 7, agent 000) — compliance checklist
results (CIS Benchmark), not security events. `search_alerts` and `alert_stats` exclude the `sca`
rule group by default so they don't drown real alerts; pass the specific `rule_id` to `search_alerts`
to fetch an SCA finding anyway. SCA alerts also carry `rule.mitre_techniques`, not `rule.mitre.id`,
so `mitre_technique` and `alert_stats group_by=mitre_technique` only ever see ordinary rule alerts.

## 5. End-to-end tests against the lab

```bash
WAZUH_E2E=1 WAZUH_API_URL=https://localhost:55000 WAZUH_API_USER=mcp-reader WAZUH_API_PASSWORD='Str0ng!ReaderPass' \
WAZUH_INDEXER_URL=https://localhost:9200 WAZUH_INDEXER_USER=mcp-reader WAZUH_INDEXER_PASSWORD='Str0ng!ReaderPass' \
TLS_INSECURE=true npm run test:e2e
```

Besides the tool checks, the suite probes the `mcp-reader` credentials against the live cluster and
fails if they can write anything or read any index outside `wazuh-alerts-*` and
`wazuh-states-vulnerabilities-*` (see T7 in `docs/threat-model.md`).

## 6. Try it

Ask Claude:

- "Which alerts of level 7 or higher happened in the last 24 hours?"
- "Which MITRE techniques appeared most today?"
- "Triage the FIM alert on db-01." (or use the `triage_alert` prompt)
- "Which agents are disconnected?"
- "List critical vulnerabilities on web-01."

Watch `audit/audit.jsonl` while you do it.
