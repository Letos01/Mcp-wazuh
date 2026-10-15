import { z } from "zod";
import { totalHits } from "../clients/indexer.js";
import { clampLimit } from "../security/policy.js";
import * as s from "./schemas.js";
import { defineTool, UNTRUSTED_NOTE } from "./types.js";

interface VulnSource {
  agent?: { id?: string; name?: string };
  package?: { name?: string; version?: string; type?: string };
  vulnerability?: {
    id?: string;
    severity?: string;
    score?: { base?: number };
    detected_at?: string;
    published_at?: string;
    reference?: string;
  };
}

export const listVulnerabilities = defineTool({
  name: "list_vulnerabilities",
  title: "List detected vulnerabilities",
  description:
    "List vulnerabilities detected by Wazuh's vulnerability detector (state index, Wazuh 4.8+), highest " +
    "CVSS first. Filter by agent and/or severity. " +
    UNTRUSTED_NOTE,
  inputSchema: z
    .object({
      agent_id: s.agentId.optional(),
      severity: s.severity.optional(),
      limit: s.limit,
    })
    .strict(),
  async handler(args, ctx) {
    const filter: unknown[] = [];
    if (args.agent_id) filter.push({ term: { "agent.id": args.agent_id } });
    if (args.severity) filter.push({ term: { "vulnerability.severity": args.severity } });
    const res = await ctx.indexer.search<VulnSource>(ctx.config.indexer.vulnIndex, {
      size: clampLimit(args.limit, 20, ctx.config.limits.maxResults),
      track_total_hits: true,
      sort: [{ "vulnerability.score.base": { order: "desc", unmapped_type: "float" } }],
      query: { bool: { filter } },
    });
    const u = ctx.untrusted;
    const items = res.hits.hits.map((h) => {
      const v = h._source;
      return {
        cve: v.vulnerability?.id,
        severity: v.vulnerability?.severity,
        cvss: v.vulnerability?.score?.base,
        package: { name: u.field(v.package?.name, `package:${h._id}`, 128), version: v.package?.version },
        agent: { id: v.agent?.id, name: u.field(v.agent?.name, `agent.name:${h._id}`, 64) },
        detected_at: v.vulnerability?.detected_at,
        reference: v.vulnerability?.reference,
      };
    });
    return { count: items.length, data: { total: totalHits(res), returned: items.length, vulnerabilities: items } };
  },
});
