#!/usr/bin/env node
// End-to-end smoke test of the BUILT server over stdio, the way Claude Desktop runs it.
// Starts the mock Wazuh, spawns `node dist/index.js`, and exercises every tool.
//   npm run build && node scripts/smoke-stdio.mjs
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const API_PORT = 15500;
const IDX_PORT = 19200;
const auditPath = join(mkdtempSync(join(tmpdir(), "mcp-wazuh-smoke-")), "audit.jsonl");

const mock = spawn(process.execPath, ["scripts/mock-wazuh.mjs"], {
  env: { ...process.env, MOCK_API_PORT: String(API_PORT), MOCK_INDEXER_PORT: String(IDX_PORT) },
  stdio: ["ignore", "inherit", "inherit"],
});
await new Promise((r) => setTimeout(r, 600));

const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/index.js"],
  env: {
    PATH: process.env.PATH,
    WAZUH_API_URL: `http://127.0.0.1:${API_PORT}`,
    WAZUH_API_USER: "mcp-reader",
    WAZUH_API_PASSWORD: "mcp-reader-pass",
    WAZUH_INDEXER_URL: `http://127.0.0.1:${IDX_PORT}`,
    WAZUH_INDEXER_USER: "mcp-reader",
    WAZUH_INDEXER_PASSWORD: "mcp-reader-pass",
    AUDIT_LOG_PATH: auditPath,
    LOG_LEVEL: "warn",
  },
  stderr: "inherit",
});
const client = new Client({ name: "smoke", version: "1.0.0" });
let failures = 0;
const check = (cond, msg) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`);
  if (!cond) failures++;
};
const call = async (name, args) => {
  const r = await client.callTool({ name, arguments: args });
  return { isError: r.isError, json: r.isError ? null : JSON.parse(r.content[0].text), text: r.content[0].text };
};

try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  check(tools.length === 7, `7 tools exposed (${tools.map((t) => t.name).join(", ")})`);

  const s = await call("search_alerts", { rule_level_min: 3 });
  check(s.json.result.returned === 11, `search_alerts returned ${s.json.result.returned} alerts`);
  check(s.json.security.injection_suspected === true, `injection flagged: ${s.json.security.reasons?.join(", ")}`);

  const brute = await call("search_alerts", { mitre_technique: "T1110.001", agent_name: "web-01" });
  check(brute.json.result.total_matches === 6, "filter by MITRE technique + agent");

  const stats = await call("alert_stats", { group_by: "mitre_technique", top: 3 });
  check(
    stats.json.result.groups[0].key === "T1110.001",
    `alert_stats top technique = ${stats.json.result.groups[0].key}`,
  );

  const fim = s.json.result.alerts.find((a) => a.rule.id === "550");
  const full = await call("get_alert", { alert_id: fim.id });
  const env = full.json.result.full_log;
  check(
    env.match(/<\/untrusted_data>/g).length === 1 && env.includes("[removed-wrapper-tag]"),
    "wrapper escape neutralized in get_alert",
  );

  const agents = await call("list_agents", { status: "disconnected" });
  check(agents.json.result.agents[0]?.name === "win-fin-07", "list_agents status=disconnected");
  const agent = await call("get_agent", { agent_id: "001" });
  check(agent.json.result.name === "web-01", "get_agent 001");
  const rule = await call("get_rule", { rule_id: 5763 });
  check(rule.json.result.mitre[0] === "T1110", "get_rule 5763");
  const vulns = await call("list_vulnerabilities", { severity: "Critical" });
  check(vulns.json.result.vulnerabilities[0]?.cve === "CVE-2024-5535", "list_vulnerabilities severity=Critical");

  const bad = await call("search_alerts", { agent_id: "1 OR 1=1" });
  check(bad.isError === true, "invalid input rejected");

  const res = await client.readResource({ uri: "wazuh://manager/info" });
  check(JSON.parse(res.contents[0].text).version === "v4.14.0", "resource wazuh://manager/info");

  await client.close();
  await new Promise((r) => setTimeout(r, 200));
  const audit = readFileSync(auditPath, "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
  check(
    audit.length >= 10 && audit.some((a) => a.outcome === "denied"),
    `audit log has ${audit.length} JSONL records incl. the rejected call (${auditPath})`,
  );
  check(!readFileSync(auditPath, "utf8").includes("mcp-reader-pass"), "no secrets in the audit log");
} catch (e) {
  console.error(e);
  failures++;
} finally {
  mock.kill();
}
console.log(failures ? `\n${failures} check(s) failed` : "\nAll smoke checks passed");
process.exit(failures ? 1 : 0);
