import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { pino } from "pino";
import type { FetchInit, FetchLike, FetchResponse } from "../src/clients/http.js";
import { IndexerClient } from "../src/clients/indexer.js";
import { WazuhApiClient } from "../src/clients/wazuhApi.js";
import { loadConfig, type Config } from "../src/config.js";
import { MemoryAuditSink } from "../src/security/audit.js";
import { RateLimiter } from "../src/security/rateLimit.js";
import { createMcpServer, type ServerDeps } from "../src/server.js";

export const API = "https://wazuh.test:55000";
export const IDX = "https://indexer.test:9200";
export const NOW = new Date("2026-10-15T12:00:00Z");

export function testConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({
    WAZUH_API_URL: API,
    WAZUH_API_USER: "mcp-reader",
    WAZUH_API_PASSWORD: "s3cret-api",
    WAZUH_INDEXER_URL: IDX,
    WAZUH_INDEXER_USER: "mcp-reader",
    WAZUH_INDEXER_PASSWORD: "s3cret-idx",
    AUDIT_LOG_PATH: "/dev/null",
    ...overrides,
  });
}

export interface Recorded {
  url: string;
  init: FetchInit;
  body?: unknown;
}

type Handler = (req: Recorded) => { status?: number; json?: unknown; delayMs?: number } | Promise<never>;

export function response(status: number, json: unknown): FetchResponse {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => json,
    text: async () => JSON.stringify(json),
  };
}

/** Programmable fake fetch: routes by "METHOD path" prefix and records every request. */
export function fakeFetch(routes: Record<string, Handler>) {
  const calls: Recorded[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const u = new URL(url);
    const rec: Recorded = { url, init, body: init.body ? JSON.parse(init.body) : undefined };
    calls.push(rec);
    const key = Object.keys(routes)
      .filter((k) => `${init.method} ${u.pathname}`.startsWith(k))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return response(404, { error: "no route" });
    const out = await routes[key](rec);
    if (out.delayMs) {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, out.delayMs);
        init.signal?.addEventListener("abort", () => {
          clearTimeout(t);
          reject(new Error("aborted"));
        });
      });
    }
    return response(out.status ?? 200, out.json ?? {});
  };
  return { fetchImpl, calls };
}

export const authRoute: Handler = () => ({ json: { data: { token: "jwt-1" }, error: 0 } });

export function items<T>(arr: T[]) {
  return { data: { affected_items: arr, total_affected_items: arr.length, failed_items: [] }, error: 0 };
}

export function hits<T>(docs: T[], total = docs.length) {
  return {
    hits: {
      total: { value: total, relation: "eq" },
      hits: docs.map((d, i) => ({ _id: `doc${i}`, _index: "wazuh-alerts-4.x-2026.10.15", _source: d })),
    },
  };
}

export function makeDeps(fetchImpl: FetchLike, configOverrides: Record<string, string> = {}) {
  const config = testConfig(configOverrides);
  const audit = new MemoryAuditSink();
  const deps: ServerDeps = {
    api: new WazuhApiClient({ ...config.wazuhApi, timeoutMs: config.limits.requestTimeoutMs, fetch: fetchImpl }),
    indexer: new IndexerClient({ ...config.indexer, timeoutMs: config.limits.requestTimeoutMs, fetch: fetchImpl }),
    config,
    audit,
    rateLimiter: new RateLimiter(config.limits.rateLimitPerMinute),
    logger: pino({ level: "silent" }),
    now: () => NOW,
  };
  return { deps, audit, config };
}

/** Connects a real MCP client to the server over an in-memory transport. */
export async function connect(deps: ServerDeps, caller = "test") {
  const server = createMcpServer(deps, caller);
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await server.connect(serverT);
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientT);
  return {
    client,
    async call(name: string, args: Record<string, unknown>) {
      const r = (await client.callTool({ name, arguments: args })) as {
        content: { type: string; text: string }[];
        isError?: boolean;
      };
      const text = r.content[0]?.text ?? "";
      let json: any;
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
      return { isError: !!r.isError, text, json };
    },
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

export const sampleAlert = (over: Record<string, unknown> = {}) => ({
  id: "1760529600.1001",
  timestamp: "2026-10-15T11:00:00.000+0000",
  agent: { id: "001", name: "web-01", ip: "10.0.0.10" },
  manager: { name: "wazuh-manager" },
  rule: {
    id: "5710",
    level: 5,
    description: "sshd: Attempt to login using a non-existent user",
    groups: ["syslog", "sshd", "authentication_failed"],
    firedtimes: 3,
    mitre: { id: ["T1110"], tactic: ["Credential Access"], technique: ["Brute Force"] },
  },
  decoder: { name: "sshd" },
  location: "/var/log/auth.log",
  full_log: "Oct 15 11:00:00 web-01 sshd[1234]: Invalid user admin from 203.0.113.5 port 52311",
  data: { srcip: "203.0.113.5", srcuser: "admin" },
  ...over,
});
