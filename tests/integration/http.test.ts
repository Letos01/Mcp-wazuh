import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { callerIdForToken } from "../../src/security/auth.js";
import { createHttpApp } from "../../src/transports/http.js";
import { authRoute, fakeFetch, items, makeDeps } from "../helpers.js";

const TOKEN = "t".repeat(48);
let app: Server;
let base: string;
let audit: ReturnType<typeof makeDeps>["audit"];

beforeAll(async () => {
  const f = fakeFetch({
    "POST /security/user/authenticate": authRoute,
    "GET /rules": () => ({ json: items([{ id: 5710, level: 5, description: "sshd" }]) }),
  });
  const made = makeDeps(f.fetchImpl, {
    MCP_TRANSPORT: "http",
    MCP_AUTH_TOKENS: TOKEN,
    MCP_ALLOWED_ORIGINS: "https://trusted.example",
  });
  audit = made.audit;
  app = createHttpApp(made.deps);
  await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => app.close(() => r())));

const initBody = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "x", version: "1" } },
};

describe("Streamable HTTP transport", () => {
  it("serves a health check without auth", async () => {
    const r = await fetch(`${base}/healthz`);
    expect(r.status).toBe(200);
  });

  it("rejects requests without a valid Bearer token and audits them", async () => {
    for (const headers of [{}, { Authorization: "Bearer wrong-token" }, { Authorization: `Basic ${TOKEN}` }]) {
      const r = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
        body: JSON.stringify(initBody),
      });
      expect(r.status).toBe(401);
      expect(r.headers.get("www-authenticate")).toContain("Bearer");
    }
    expect(audit.records.filter((r) => r.kind === "auth" && r.outcome === "denied").length).toBeGreaterThanOrEqual(3);
  });

  it("rejects oversized bodies and unknown paths", async () => {
    const big = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ x: "a".repeat(300 * 1024) }),
    });
    expect(big.status).toBe(413);
    expect((await fetch(`${base}/admin`)).status).toBe(404);
    const get = await fetch(`${base}/mcp`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(get.status).toBe(405);
  });

  it("works end to end with the official MCP client", async () => {
    const client = new Client({ name: "http-test", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
    });
    await client.connect(transport);
    const tools = await client.listTools();
    expect(tools.tools).toHaveLength(7);
    const r = (await client.callTool({ name: "get_rule", arguments: { rule_id: 5710 } })) as {
      content: { text: string }[];
    };
    expect(JSON.parse(r.content[0].text).result.id).toBe(5710);
    await client.close();

    const toolRecord = audit.records.find((r) => r.kind === "tool" && r.name === "get_rule");
    expect(toolRecord?.caller).toBe(callerIdForToken(TOKEN));
    expect(JSON.stringify(audit.records)).not.toContain(TOKEN);
  });

  it("rejects browser requests from origins that are not allowed (DNS rebinding)", async () => {
    const post = (origin: string) =>
      fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${TOKEN}`,
          Origin: origin,
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify(initBody),
      });
    expect((await post("https://evil.example")).status).toBe(403);
    expect((await post("https://trusted.example")).status).toBe(200);
  });

  // keep last: it exhausts the failed-auth budget for 127.0.0.1
  it("limits failed authentication per IP and stops auditing the flood", async () => {
    const before = audit.records.filter((r) => r.kind === "auth").length;
    const statuses: number[] = [];
    for (let i = 0; i < 30; i++) {
      const r = await fetch(`${base}/mcp`, { method: "POST", headers: { Authorization: "Bearer nope" }, body: "{}" });
      statuses.push(r.status);
    }
    expect(statuses).toContain(429);
    const audited = audit.records.filter((r) => r.kind === "auth").length - before;
    expect(audited).toBeLessThanOrEqual(20);
  });
});
