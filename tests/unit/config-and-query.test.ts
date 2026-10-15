import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "../../src/config.js";
import { JsonlAuditSink } from "../../src/security/audit.js";
import { buildAlertQuery } from "../../src/tools/alerts.js";
import { testConfig } from "../helpers.js";

describe("config", () => {
  it("applies secure defaults", () => {
    const c = testConfig();
    expect(c.transport).toBe("stdio");
    expect(c.tls.insecure).toBe(false);
    expect(c.http.host).toBe("127.0.0.1");
    expect(c.limits.maxResults).toBe(50);
    expect(c.limits.maxTimeWindowDays).toBe(30);
    expect(c.wazuhApi.url).toBe("https://wazuh.test:55000");
  });

  it("fails without leaking secret values", () => {
    try {
      loadConfig({ WAZUH_API_URL: "not a url", WAZUH_API_PASSWORD: "topsecret" });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      expect((e as Error).message).toContain("WAZUH_API_URL");
      expect((e as Error).message).not.toContain("topsecret");
    }
  });

  it("requires strong tokens in HTTP mode", () => {
    expect(() => testConfig({ MCP_TRANSPORT: "http" })).toThrow(/MCP_AUTH_TOKENS/);
    expect(() => testConfig({ MCP_TRANSPORT: "http", MCP_AUTH_TOKENS: "short" })).toThrow(/32 characters/);
    const c = testConfig({ MCP_TRANSPORT: "http", MCP_AUTH_TOKENS: `${"a".repeat(32)}, ${"b".repeat(40)}` });
    expect(c.http.authTokens).toHaveLength(2);
  });
});

describe("buildAlertQuery", () => {
  const range = { from: "2026-10-14T12:00:00.000Z", to: "2026-10-15T12:00:00.000Z" };

  it("builds only structured filters", () => {
    const q = buildAlertQuery(
      { agent_id: "001", agent_name: "web-01", rule_level_min: 10, rule_id: 5710, mitre_technique: "T1110" },
      range,
    );
    expect(q.bool.filter).toEqual([
      { range: { timestamp: { gte: range.from, lte: range.to } } },
      { term: { "agent.id": "001" } },
      { term: { "agent.name": "web-01" } },
      { range: { "rule.level": { gte: 10 } } },
      { term: { "rule.id": "5710" } },
      { term: { "rule.mitre.id": "T1110" } },
    ]);
    expect(q.bool.must).toEqual([]);
  });

  it("turns free text into an operator-free simple_query_string", () => {
    const q = buildAlertQuery({ text: 'admin" OR * | -(x)' }, range);
    expect(q.bool.must[0]).toEqual({
      simple_query_string: {
        query: 'admin" OR * | -(x)',
        fields: ["full_log", "rule.description"],
        flags: "NONE",
        default_operator: "and",
      },
    });
  });
});

describe("JsonlAuditSink", () => {
  it("appends one JSON line per record, in order, with secrets redacted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const path = join(dir, "sub", "audit.jsonl");
    const sink = new JsonlAuditSink(path);
    await Promise.all([
      sink.write({ ts: "1", caller: "c", kind: "tool", name: "a", outcome: "ok", params: { password: "p" } }),
      sink.write({ ts: "2", caller: "c", kind: "tool", name: "b", outcome: "error" }),
    ]);
    const lines = readFileSync(path, "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(lines.map((l) => l.name)).toEqual(["a", "b"]);
    expect(lines[0].params.password).toBe("[redacted]");
  });
});
