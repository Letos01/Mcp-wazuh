/**
 * End-to-end test against a live Wazuh (lab) seeded with scripts/seed-lab-alerts.mjs.
 * Skipped unless WAZUH_E2E=1. Uses the same environment variables as the server.
 *
 *   WAZUH_E2E=1 WAZUH_API_URL=... WAZUH_INDEXER_URL=... (etc.) npm run test:e2e
 */
import { pino } from "pino";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createFetch } from "../../src/clients/http.js";
import { IndexerClient } from "../../src/clients/indexer.js";
import { WazuhApiClient } from "../../src/clients/wazuhApi.js";
import { loadConfig } from "../../src/config.js";
import { MemoryAuditSink } from "../../src/security/audit.js";
import { RateLimiter } from "../../src/security/rateLimit.js";
import { connect } from "../helpers.js";

const enabled = process.env.WAZUH_E2E === "1";

describe.runIf(enabled)("live Wazuh", () => {
  let session: Awaited<ReturnType<typeof connect>>;
  const audit = new MemoryAuditSink();

  beforeAll(async () => {
    const config = loadConfig({ AUDIT_LOG_PATH: "/dev/null", ...process.env });
    const fetchImpl = createFetch(config.tls);
    session = await connect({
      api: new WazuhApiClient({ ...config.wazuhApi, timeoutMs: config.limits.requestTimeoutMs, fetch: fetchImpl }),
      indexer: new IndexerClient({ ...config.indexer, timeoutMs: config.limits.requestTimeoutMs, fetch: fetchImpl }),
      config,
      audit,
      rateLimiter: new RateLimiter(1000),
      logger: pino({ level: "silent" }),
    });
  });
  afterAll(() => session?.close());

  it("reads manager info and lists agents", async () => {
    const info = await session.client.readResource({ uri: "wazuh://manager/info" });
    expect(JSON.parse((info.contents[0] as { text: string }).text).version).toMatch(/^v4\./);
    const agents = await session.call("list_agents", {});
    expect(agents.isError).toBe(false);
    expect(agents.json.result.agents.length).toBeGreaterThan(0);
  });

  it("finds the seeded brute-force alerts and explains the rule", async () => {
    const r = await session.call("search_alerts", { mitre_technique: "T1110.001" });
    expect(r.json.result.total_matches).toBeGreaterThanOrEqual(6);
    const rule = await session.call("get_rule", { rule_id: 5710 });
    expect(rule.json.result.level).toBe(5);
  });

  it("flags the seeded prompt-injection payloads and keeps them enveloped", async () => {
    const r = await session.call("search_alerts", { rule_level_min: 6 });
    expect(r.json.security.injection_suspected).toBe(true);
    const fim = r.json.result.alerts.find((a: { rule: { id: string } }) => a.rule.id === "550");
    const full = await session.call("get_alert", { alert_id: fim.id });
    expect(full.json.result.full_log.match(/<\/untrusted_data>/g)).toHaveLength(1);
  });

  it("aggregates by MITRE technique", async () => {
    const r = await session.call("alert_stats", { group_by: "mitre_technique" });
    expect(r.json.result.groups.length).toBeGreaterThan(0);
  });
});
