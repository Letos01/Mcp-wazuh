import { z } from "zod";
import { totalHits } from "../clients/indexer.js";
import { NotFoundError } from "../errors.js";
import { clampLimit, resolveTimeRange } from "../security/policy.js";
import type { UntrustedCollector } from "../security/sanitize.js";
import * as s from "./schemas.js";
import { defineTool, UNTRUSTED_NOTE, type AlertSource } from "./types.js";

const SUMMARY_FIELDS = ["id", "timestamp", "agent", "rule", "decoder.name", "location", "full_log"];
const LOG_EXCERPT_CHARS = 500;

export function summarizeAlert(src: AlertSource, u: UntrustedCollector) {
  const id = src.id ?? "unknown";
  return {
    id,
    timestamp: src.timestamp,
    agent: { id: src.agent?.id, name: u.field(src.agent?.name, `agent.name:${id}`, 64) },
    rule: {
      id: src.rule?.id,
      level: src.rule?.level,
      description: u.field(src.rule?.description, `rule.description:${id}`),
      mitre: src.rule?.mitre?.id ?? [],
    },
    log_excerpt: src.full_log ? u.wrap(src.full_log, "wazuh_alert.full_log", id, LOG_EXCERPT_CHARS) : null,
  };
}

/** Builds the OpenSearch query from validated arguments only. */
export function buildAlertQuery(
  args: {
    agent_id?: string;
    agent_name?: string;
    rule_level_min?: number;
    rule_id?: number;
    mitre_technique?: string;
    text?: string;
  },
  range: { from: string; to: string },
) {
  const filter: unknown[] = [{ range: { timestamp: { gte: range.from, lte: range.to } } }];
  if (args.agent_id) filter.push({ term: { "agent.id": args.agent_id } });
  if (args.agent_name) filter.push({ term: { "agent.name": args.agent_name } });
  if (args.rule_level_min !== undefined) filter.push({ range: { "rule.level": { gte: args.rule_level_min } } });
  if (args.rule_id !== undefined) filter.push({ term: { "rule.id": String(args.rule_id) } });
  if (args.mitre_technique) filter.push({ term: { "rule.mitre.id": args.mitre_technique } });
  // SCA (Security Configuration Assessment) findings are compliance checklist results, not security
  // events: they can outnumber real alerts on a live manager and skew both search and aggregation.
  // Excluded by default; an explicit rule_id still reaches them.
  if (args.rule_id === undefined) filter.push({ bool: { must_not: [{ term: { "rule.groups": "sca" } }] } });

  const must: unknown[] = [];
  if (args.text) {
    must.push({
      simple_query_string: {
        query: args.text,
        fields: ["full_log", "rule.description"],
        // NONE disables every operator: the text is matched literally, no query syntax injection.
        flags: "NONE",
        default_operator: "and",
      },
    });
  }
  return { bool: { filter, must } };
}

export const searchAlerts = defineTool({
  name: "search_alerts",
  title: "Search Wazuh alerts",
  description:
    "Search security alerts in the Wazuh Indexer, newest first. Use it to answer questions like " +
    "'level >= 10 alerts on web-01 in the last 24h' or 'alerts for MITRE T1110 this week'. " +
    "Excludes SCA (Security Configuration Assessment) findings by default, since those are compliance " +
    "checklist results, not security events; pass the specific rule_id to fetch one anyway. " +
    "Returns a summary per alert; call get_alert for full details. The window defaults to the last 24h and " +
    "cannot exceed the server's maximum (default 30 days). " +
    UNTRUSTED_NOTE,
  inputSchema: z
    .object({
      time_from: s.timeFrom,
      time_to: s.timeTo,
      agent_id: s.agentId.optional(),
      agent_name: s.agentName.optional(),
      rule_level_min: z.number().int().min(0).max(15).optional().describe("Minimum rule level (0-15)"),
      rule_id: s.ruleId.optional(),
      mitre_technique: s.mitreTechnique.optional(),
      text: s.freeText.optional(),
      limit: s.limit,
    })
    .strict(),
  async handler(args, ctx) {
    const { maxResults, maxTimeWindowDays } = ctx.config.limits;
    const range = resolveTimeRange(args.time_from, args.time_to, maxTimeWindowDays, ctx.now());
    const size = clampLimit(args.limit, 20, maxResults);
    const res = await ctx.indexer.search<AlertSource>(ctx.config.indexer.alertsIndex, {
      size,
      track_total_hits: true,
      sort: [{ timestamp: { order: "desc" } }],
      _source: SUMMARY_FIELDS,
      query: buildAlertQuery(args, range),
    });
    const alerts = res.hits.hits.map((h) => summarizeAlert(h._source, ctx.untrusted));
    return {
      count: alerts.length,
      data: { time_range: range, total_matches: totalHits(res), returned: alerts.length, alerts },
    };
  },
});

export const getAlert = defineTool({
  name: "get_alert",
  title: "Get one Wazuh alert",
  description:
    "Fetch the full details of a single alert by its Wazuh alert id (from search_alerts): rule, agent, " +
    "decoder, location, full log and decoded data fields. " +
    UNTRUSTED_NOTE,
  inputSchema: z.object({ alert_id: s.alertId }).strict(),
  async handler(args, ctx) {
    const res = await ctx.indexer.search<AlertSource>(ctx.config.indexer.alertsIndex, {
      size: 1,
      query: { bool: { filter: [{ term: { id: args.alert_id } }] } },
    });
    const hit = res.hits.hits[0];
    if (!hit) throw new NotFoundError(`alert ${args.alert_id} not found`);
    const src = hit._source;
    const u = ctx.untrusted;
    const id = src.id ?? args.alert_id;
    return {
      count: 1,
      data: {
        id,
        timestamp: src.timestamp,
        agent: { id: src.agent?.id, name: u.field(src.agent?.name, `agent.name:${id}`, 64), ip: src.agent?.ip },
        manager: src.manager?.name,
        rule: {
          id: src.rule?.id,
          level: src.rule?.level,
          description: u.field(src.rule?.description, `rule.description:${id}`),
          groups: src.rule?.groups ?? [],
          fired_times: src.rule?.firedtimes,
          mitre: {
            ids: src.rule?.mitre?.id ?? [],
            tactics: src.rule?.mitre?.tactic ?? [],
            techniques: src.rule?.mitre?.technique ?? [],
          },
        },
        decoder: src.decoder?.name,
        location: u.field(src.location, `location:${id}`),
        full_log: src.full_log ? u.wrap(src.full_log, "wazuh_alert.full_log", id) : null,
        data: src.data ? u.wrap(src.data, "wazuh_alert.data", id) : null,
      },
    };
  },
});

const GROUP_FIELDS = {
  rule: "rule.id",
  agent: "agent.name",
  mitre_technique: "rule.mitre.id",
  level: "rule.level",
} as const;

interface Bucket {
  key: string | number;
  doc_count: number;
  label?: { buckets?: { key: string }[] };
}

export const alertStats = defineTool({
  name: "alert_stats",
  title: "Aggregate Wazuh alerts",
  description:
    "Count alerts in a time window grouped by rule, agent, MITRE technique or level. Use it for " +
    "'which techniques appeared most this week' or 'noisiest agents today'. Excludes SCA (Security " +
    "Configuration Assessment) findings, since those are compliance checklist results, not security " +
    "events, and would otherwise dominate the counts. " +
    UNTRUSTED_NOTE,
  inputSchema: z
    .object({
      time_from: s.timeFrom,
      time_to: s.timeTo,
      group_by: z.enum(["rule", "agent", "mitre_technique", "level"]),
      rule_level_min: z.number().int().min(0).max(15).optional(),
      top: z.number().int().min(1).max(50).optional().describe("Number of groups to return (default 10)"),
    })
    .strict(),
  async handler(args, ctx) {
    const range = resolveTimeRange(args.time_from, args.time_to, ctx.config.limits.maxTimeWindowDays, ctx.now());
    const field = GROUP_FIELDS[args.group_by];
    const top = clampLimit(args.top, 10, 50);
    const terms: Record<string, unknown> = { terms: { field, size: top } };
    if (args.group_by === "rule") {
      terms.aggs = { label: { terms: { field: "rule.description", size: 1 } } };
    }
    const res = await ctx.indexer.search<never>(ctx.config.indexer.alertsIndex, {
      size: 0,
      track_total_hits: true,
      query: buildAlertQuery({ rule_level_min: args.rule_level_min }, range),
      aggs: { groups: terms },
    });
    const buckets = ((res.aggregations?.groups as { buckets?: Bucket[] })?.buckets ?? []).map((b) => ({
      key: typeof b.key === "string" ? ctx.untrusted.field(b.key, `group.${args.group_by}`, 128) : b.key,
      count: b.doc_count,
      ...(b.label?.buckets?.[0]
        ? { description: ctx.untrusted.field(b.label.buckets[0].key, `group.label:${b.key}`) }
        : {}),
    }));
    return {
      count: buckets.length,
      data: { time_range: range, group_by: args.group_by, total_alerts: totalHits(res), groups: buckets },
    };
  },
});
