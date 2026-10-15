#!/usr/bin/env node
// Minimal mock of the Wazuh Server API + Wazuh Indexer for demos and smoke tests.
// It implements only what mcp-wazuh calls, over plain HTTP, with in-memory sample data
// (including prompt-injection payloads). NOT a Wazuh replacement.
//
//   node scripts/mock-wazuh.mjs            # API on :55000, Indexer on :9200
//   MOCK_API_PORT=15500 MOCK_INDEXER_PORT=19200 node scripts/mock-wazuh.mjs
import { createServer } from "node:http";
import { sampleAgents, sampleAlerts, sampleRules, sampleVulnerabilities } from "./sample-alerts.mjs";

const HOST = process.env.MOCK_HOST ?? "127.0.0.1";
const API_PORT = Number(process.env.MOCK_API_PORT ?? 55000);
const IDX_PORT = Number(process.env.MOCK_INDEXER_PORT ?? 9200);
const USER = process.env.MOCK_USER ?? "mcp-reader";
const PASS = process.env.MOCK_PASSWORD ?? "mcp-reader-pass";
const TOKEN = "mock-jwt-token";

const alerts = process.env.MOCK_EMPTY === "1" ? [] : sampleAlerts();

const json = (res, status, body) => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};
const basic = (u, p) => "Basic " + Buffer.from(`${u}:${p}`).toString("base64");
const basicOk = (req) =>
  req.headers.authorization === basic(USER, PASS) || req.headers.authorization === basic("admin", "SecretPassword");
const items = (arr) => ({
  data: { affected_items: arr, total_affected_items: arr.length, total_failed_items: 0, failed_items: [] },
  error: 0,
});
const get = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
const readBody = async (req) => {
  let raw = "";
  for await (const c of req) raw += c;
  return raw ? JSON.parse(raw) : {};
};

// ---- Wazuh Server API ----
createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.method === "POST" && url.pathname === "/security/user/authenticate") {
    return basicOk(req)
      ? json(res, 200, { data: { token: TOKEN }, error: 0 })
      : json(res, 401, { title: "Unauthorized" });
  }
  if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(res, 401, { title: "Unauthorized" });
  const q = url.searchParams;
  switch (url.pathname) {
    case "/agents": {
      let list = sampleAgents;
      if (q.get("agents_list")) list = list.filter((a) => q.get("agents_list").split(",").includes(a.id));
      if (q.get("status")) list = list.filter((a) => q.get("status").split(",").includes(a.status));
      if (q.get("os.platform")) list = list.filter((a) => a.os.platform === q.get("os.platform"));
      if (q.get("group")) list = list.filter((a) => a.group.includes(q.get("group")));
      return json(res, 200, items(list.slice(0, Number(q.get("limit") ?? 500))));
    }
    case "/rules":
      return json(res, 200, items(sampleRules.filter((r) => String(r.id) === q.get("rule_ids"))));
    case "/manager/info":
      return json(
        res,
        200,
        items([
          {
            path: "/var/ossec",
            version: "v4.14.0",
            type: "server",
            max_agents: "unlimited",
            tz_name: "UTC",
            uuid: "00000000-mock-mock-mock-000000000000",
          },
        ]),
      );
    case "/security/users/me":
      return json(res, 200, items([{ id: 100, username: USER, roles: [2] }]));
    default:
      return json(res, 404, { title: "Not Found" });
  }
}).listen(API_PORT, HOST, () => console.error(`mock Wazuh API     http://${HOST}:${API_PORT}`));

// ---- Wazuh Indexer (OpenSearch _search subset) ----
function matches(doc, clause) {
  if (clause.term) {
    const [field, value] = Object.entries(clause.term)[0];
    const v = get(doc, field);
    return Array.isArray(v) ? v.map(String).includes(String(value)) : String(v) === String(value);
  }
  if (clause.range) {
    const [field, r] = Object.entries(clause.range)[0];
    const v = get(doc, field);
    if (v === undefined) return false;
    const cmp = typeof r.gte === "number" || typeof r.lte === "number" ? Number(v) : new Date(v).getTime();
    const norm = (x) => (typeof x === "number" ? x : new Date(x).getTime());
    return (r.gte === undefined || cmp >= norm(r.gte)) && (r.lte === undefined || cmp <= norm(r.lte));
  }
  if (clause.simple_query_string) {
    const { query, fields } = clause.simple_query_string;
    const hay = fields
      .map((f) => String(get(doc, f) ?? ""))
      .join(" ")
      .toLowerCase();
    return query
      .toLowerCase()
      .split(/\s+/)
      .every((w) => hay.includes(w));
  }
  return true;
}

createServer(async (req, res) => {
  if (!basicOk(req)) return json(res, 401, { error: "unauthorized" });
  const url = new URL(req.url, "http://x");
  const bulk = /^\/([^/]+)\/_bulk$/.exec(decodeURIComponent(url.pathname));
  if (req.method === "POST" && bulk) {
    // Minimal _bulk support so scripts/seed-lab-alerts.mjs can be tested against the mock.
    let raw = "";
    for await (const c of req) raw += c;
    const lines = raw.split("\n").filter(Boolean);
    const results = [];
    for (let i = 0; i + 1 < lines.length; i += 2) {
      alerts.push(JSON.parse(lines[i + 1]));
      results.push({ index: { _index: bulk[1], status: 201 } });
    }
    return json(res, 200, { errors: false, items: results });
  }
  const m = /^\/([^/]+)\/_search$/.exec(decodeURIComponent(url.pathname));
  if (req.method !== "POST" || !m) return json(res, 404, { error: "not_found" });
  const body = await readBody(req);
  const source = m[1].startsWith("wazuh-states-vulnerabilities") ? sampleVulnerabilities : alerts;
  const clauses = [...(body.query?.bool?.filter ?? []), ...(body.query?.bool?.must ?? [])];
  let docs = source.filter((d) => clauses.every((c) => matches(d, c)));
  const total = docs.length;
  if (body.sort?.[0]?.timestamp) docs = [...docs].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  if (body.sort?.[0]?.["vulnerability.score.base"])
    docs = [...docs].sort((a, b) => b.vulnerability.score.base - a.vulnerability.score.base);

  let aggregations;
  const terms = body.aggs?.groups?.terms;
  if (terms) {
    const counts = new Map();
    const labels = new Map();
    for (const d of docs) {
      const raw = get(d, terms.field);
      for (const k of Array.isArray(raw) ? raw : [raw]) {
        if (k === undefined) continue;
        counts.set(k, (counts.get(k) ?? 0) + 1);
        labels.set(k, d.rule?.description);
      }
    }
    const buckets = [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, terms.size)
      .map(([key, doc_count]) => ({
        key,
        doc_count,
        ...(body.aggs.groups.aggs?.label ? { label: { buckets: [{ key: labels.get(key), doc_count }] } } : {}),
      }));
    aggregations = { groups: { buckets } };
  }
  json(res, 200, {
    hits: {
      total: { value: total, relation: "eq" },
      hits: docs.slice(0, body.size ?? 10).map((d, i) => ({ _index: m[1], _id: `mock-${i}`, _source: d })),
    },
    ...(aggregations ? { aggregations } : {}),
  });
}).listen(IDX_PORT, HOST, () => console.error(`mock Wazuh Indexer http://${HOST}:${IDX_PORT}`));
