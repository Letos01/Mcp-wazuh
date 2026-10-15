#!/usr/bin/env node
// LAB ONLY: indexes the sample alerts (including prompt-injection payloads) into a
// Wazuh Indexer so you can demo mcp-wazuh without waiting for real attacks.
// Uses an ADMIN indexer account on purpose (writing) - never give these
// credentials to mcp-wazuh itself.
//
//   LAB_INDEXER_URL=https://localhost:9200 LAB_INDEXER_USER=admin LAB_INDEXER_PASSWORD=SecretPassword \
//   LAB_INSECURE=1 node scripts/seed-lab-alerts.mjs
import { Agent, fetch } from "undici";
import { sampleAlerts } from "./sample-alerts.mjs";

const url = (process.env.LAB_INDEXER_URL ?? "https://localhost:9200").replace(/\/+$/, "");
const user = process.env.LAB_INDEXER_USER ?? "admin";
const password = process.env.LAB_INDEXER_PASSWORD ?? "SecretPassword";
const insecure = process.env.LAB_INSECURE === "1";

const now = new Date();
const day = now.toISOString().slice(0, 10).replace(/-/g, ".");
const index = `wazuh-alerts-4.x-${day}`;
const alerts = sampleAlerts(now);

const body = alerts.map((a) => `${JSON.stringify({ index: {} })}\n${JSON.stringify(a)}\n`).join("");
const res = await fetch(`${url}/${index}/_bulk?refresh=true`, {
  method: "POST",
  headers: {
    Authorization: "Basic " + Buffer.from(`${user}:${password}`).toString("base64"),
    "Content-Type": "application/x-ndjson",
  },
  body,
  dispatcher: new Agent({ connect: { rejectUnauthorized: !insecure } }),
});
const out = await res.json();
if (!res.ok || out.errors) {
  console.error(`seeding failed (HTTP ${res.status})`, JSON.stringify(out).slice(0, 500));
  process.exit(1);
}
console.log(`Indexed ${alerts.length} sample alerts into ${index}`);
console.log("Alert ids:", alerts.map((a) => `${a.id} (rule ${a.rule.id})`).join(", "));
