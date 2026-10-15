/**
 * End-to-end test against a live Wazuh (lab) seeded with scripts/seed-lab-alerts.mjs.
 * Skipped unless WAZUH_E2E=1. Uses the same environment variables as the server.
 *
 *   WAZUH_E2E=1 WAZUH_API_URL=... WAZUH_INDEXER_URL=... (etc.) npm run test:e2e
 */
import { pino } from "pino";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { basicAuth, createFetch, type FetchInit } from "../../src/clients/http.js";
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

  // The live manager's own SCA scan (CIS Benchmark compliance checks, not security events) writes
  // hundreds of level-7 alerts (rule 19007-19009); confirm they stay out of alerts/stats by default,
  // but a specific rule_id still reaches one.
  it("excludes SCA compliance findings by default, but not when asked for by rule_id", async () => {
    const broad = await session.call("search_alerts", { rule_level_min: 6, limit: 500 });
    const scaIds = broad.json.result.alerts.filter((a: { rule: { id: string } }) => a.rule.id.startsWith("1900"));
    expect(scaIds).toHaveLength(0);

    const stats = await session.call("alert_stats", { group_by: "rule", top: 50 });
    expect(stats.json.result.groups.some((g: { key: string }) => g.key.startsWith("1900"))).toBe(false);

    const explicit = await session.call("search_alerts", { rule_id: 19007 });
    expect(explicit.json.result.alerts.length).toBeGreaterThan(0);
  });

  it("flags the seeded prompt-injection payloads", async () => {
    const r = await session.call("search_alerts", { rule_id: 31106 });
    expect(r.json.result.alerts.length).toBeGreaterThan(0);
    expect(r.json.security.injection_suspected).toBe(true);
    expect(r.json.security.reasons).toContain("override_instructions");
  });

  it("keeps a wrapper-breaking log inside a single envelope", async () => {
    const r = await session.call("search_alerts", { rule_id: 550 });
    const fim = r.json.result.alerts.find((a: { rule: { id: string } }) => a.rule.id === "550");
    expect(fim).toBeDefined();
    const full = await session.call("get_alert", { alert_id: fim.id });
    expect(full.json.result.full_log.match(/<\/untrusted_data>/g)).toHaveLength(1);
  });

  it("aggregates by MITRE technique", async () => {
    const r = await session.call("alert_stats", { group_by: "mitre_technique" });
    expect(r.json.result.groups.length).toBeGreaterThan(0);
  });
});

/**
 * Proves the claim behind T7 in docs/threat-model.md against the live cluster:
 * the credentials mcp-wazuh is given cannot write anything and cannot read any
 * index outside the two patterns it needs. Run by lab-up.sh on every lab build.
 */
describe.runIf(enabled)("least privilege of the mcp-reader credentials", () => {
  const config = enabled ? loadConfig({ AUDIT_LOG_PATH: "/dev/null", ...process.env }) : undefined!;
  const idx = (path: string, init: Partial<FetchInit> = {}) =>
    createFetch(config.tls)(`${config.indexer.url}${path}`, {
      method: "GET",
      headers: {
        Authorization: basicAuth(config.indexer.user, config.indexer.password),
        "Content-Type": "application/json",
      },
      ...init,
    });
  const ALERT_DOC = `/${"wazuh-alerts-4.x-*".replace("*", new Date().toISOString().slice(0, 10).replace(/-/g, "."))}`;

  it("can read the two index patterns it needs", async () => {
    for (const pattern of [config.indexer.alertsIndex, config.indexer.vulnIndex]) {
      const res = await idx(`/${pattern}/_search`, { method: "POST", body: JSON.stringify({ size: 0 }) });
      expect(res.status, pattern).toBe(200);
    }
  });

  it("cannot write, delete or reshape the alerts index", async () => {
    const denied = [
      [`${ALERT_DOC}/_doc`, "POST", JSON.stringify({ injected: true })],
      [`${ALERT_DOC}/_delete_by_query`, "POST", JSON.stringify({ query: { match_all: {} } })],
      [`${ALERT_DOC}/_update_by_query`, "POST", undefined],
      [`${ALERT_DOC}/_doc/any-id`, "DELETE", undefined],
      [`${ALERT_DOC}/_mapping`, "PUT", JSON.stringify({ properties: { x: { type: "keyword" } } })],
      [`${ALERT_DOC}/_settings`, "PUT", JSON.stringify({ index: { number_of_replicas: 0 } })],
      ["/pwned-by-mcp", "PUT", undefined],
      // a real setting: OpenSearch validates an empty body before it checks authorization
      ["/_cluster/settings", "PUT", JSON.stringify({ persistent: { "action.destructive_requires_name": false } })],
      ["/_plugins/_security/api/roles/pwn", "PUT", JSON.stringify({ cluster_permissions: ["*"] })],
    ] as const;
    for (const [path, method, body] of denied) {
      const res = await idx(path, { method: method as FetchInit["method"], body });
      expect(res.status, `${method} ${path}`).toBe(403);
    }
  });

  // _bulk, _mget and _msearch answer 200 with per-item 403s, so the status is not enough.
  it("is rejected per item by the multi-document APIs", async () => {
    const bulk = await idx("/_bulk?refresh=true", {
      method: "POST",
      headers: {
        Authorization: basicAuth(config.indexer.user, config.indexer.password),
        "Content-Type": "application/x-ndjson",
      },
      body: `${JSON.stringify({ index: { _index: ALERT_DOC.slice(1), _id: "probe-write" } })}\n${JSON.stringify({ injected: true })}\n`,
    });
    const items = (await bulk.json()) as { errors: boolean; items: { index: { status: number } }[] };
    expect(items.errors).toBe(true);
    expect(items.items[0].index.status).toBe(403);

    const mget = await idx("/_mget", {
      method: "POST",
      body: JSON.stringify({ docs: [{ _index: ".opendistro_security", _id: "internalusers" }] }),
    });
    const docs = (await mget.json()) as { docs: { error?: unknown; _source?: unknown }[] };
    expect(docs.docs[0].error).toBeDefined();
    expect(docs.docs[0]._source).toBeUndefined();
  });

  it("cannot read any other index, nor enumerate the cluster", async () => {
    const searches = [
      "/*/_search",
      "/_all/_search",
      "/_search",
      "/.opendistro_security/_search",
      "/.kibana/_search",
      "/wazuh-statistics-*/_search",
      "/wazuh-states-inventory-packages-*/_search",
      // one granted pattern plus one that is not: the whole request must fail
      `/${config.indexer.alertsIndex},wazuh-statistics-*/_search`,
    ];
    for (const path of searches) {
      const res = await idx(path, { method: "POST", body: JSON.stringify({ size: 1 }) });
      expect(res.status, `POST ${path}`).toBe(403);
    }
    for (const path of ["/_cat/indices", "/_cluster/health", "/_plugins/_security/api/internalusers"]) {
      const res = await idx(path);
      expect(res.status, `GET ${path}`).toBe(403);
    }
  });

  it("holds no write action on the Wazuh API either", async () => {
    const api = new WazuhApiClient({
      ...config.wazuhApi,
      timeoutMs: config.limits.requestTimeoutMs,
      fetch: createFetch(config.tls),
    });
    expect(await api.isAdministrator()).toBe(false);

    const fetchImpl = createFetch(config.tls);
    const token = await fetchImpl(`${config.wazuhApi.url}/security/user/authenticate?raw=true`, {
      method: "POST",
      headers: { Authorization: basicAuth(config.wazuhApi.user, config.wazuhApi.password) },
    }).then((r) => r.text());
    const write = [
      ["/agents", JSON.stringify({ name: "pwned-by-mcp" })],
      ["/groups", JSON.stringify({ group_id: "pwned-by-mcp" })],
      ["/security/users", JSON.stringify({ username: "pwned", password: "Str0ng!Pass123" })],
      ["/security/users/100/roles?role_ids=1", undefined],
    ] as const;
    for (const [path, body] of write) {
      const res = await fetchImpl(`${config.wazuhApi.url}${path}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body,
      });
      expect(res.status, `POST ${path}`).toBe(403);
    }
  });
});
