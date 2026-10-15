import { z } from "zod";
import type { WazuhAgent } from "../clients/wazuhApi.js";
import { NotFoundError } from "../errors.js";
import { clampLimit } from "../security/policy.js";
import type { UntrustedCollector } from "../security/sanitize.js";
import * as s from "./schemas.js";
import { defineTool, UNTRUSTED_NOTE } from "./types.js";

function presentAgent(a: WazuhAgent, u: UntrustedCollector) {
  return {
    id: a.id,
    // Agent names are chosen at enrollment time and can be attacker-controlled.
    name: u.field(a.name, `agent.name:${a.id}`, 64),
    ip: a.ip,
    status: a.status,
    version: a.version,
    os: a.os ? { name: a.os.name, platform: a.os.platform, version: a.os.version } : undefined,
    groups: a.group ?? [],
    last_keepalive: a.lastKeepAlive,
  };
}

export const listAgents = defineTool({
  name: "list_agents",
  title: "List Wazuh agents",
  description:
    "List Wazuh agents with id, name, IP, OS, status, version and last keepalive. Filter by status " +
    "(e.g. 'disconnected' to find endpoints that stopped reporting), OS platform or group. " +
    UNTRUSTED_NOTE,
  inputSchema: z
    .object({
      status: s.agentStatus.optional(),
      os: s.osPlatform.optional(),
      group: s.group.optional(),
      limit: s.limit,
    })
    .strict(),
  async handler(args, ctx) {
    const res = await ctx.api.listAgents({
      status: args.status,
      platform: args.os,
      group: args.group,
      limit: clampLimit(args.limit, 50, ctx.config.limits.maxResults),
    });
    const agents = res.data.affected_items.map((a) => presentAgent(a, ctx.untrusted));
    return { count: agents.length, data: { total: res.data.total_affected_items, agents } };
  },
});

export const getAgent = defineTool({
  name: "get_agent",
  title: "Get one Wazuh agent",
  description: "Get details of one Wazuh agent by id. " + UNTRUSTED_NOTE,
  inputSchema: z.object({ agent_id: s.agentId }).strict(),
  async handler(args, ctx) {
    const res = await ctx.api.getAgent(args.agent_id);
    const agent = res.data.affected_items[0];
    if (!agent) throw new NotFoundError(`agent ${args.agent_id} not found`);
    const a = presentAgent(agent, ctx.untrusted);
    return {
      count: 1,
      data: { ...a, os: agent.os, date_added: agent.dateAdd, node: agent.node_name },
    };
  },
});
