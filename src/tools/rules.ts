import { z } from "zod";
import { NotFoundError } from "../errors.js";
import * as s from "./schemas.js";
import { defineTool } from "./types.js";

export const getRule = defineTool({
  name: "get_rule",
  title: "Get a Wazuh rule",
  description:
    "Get the definition of a Wazuh detection rule by id: description, level, groups, MITRE ATT&CK " +
    "mapping and compliance tags (PCI DSS, GDPR, HIPAA, NIST 800-53, TSC). Use it to explain why an alert fired.",
  inputSchema: z.object({ rule_id: s.ruleId }).strict(),
  async handler(args, ctx) {
    const res = await ctx.api.getRule(args.rule_id);
    const r = res.data.affected_items[0];
    if (!r) throw new NotFoundError(`rule ${args.rule_id} not found`);
    return {
      count: 1,
      data: {
        id: r.id,
        level: r.level,
        description: ctx.untrusted.field(r.description, `rule:${r.id}`),
        groups: r.groups ?? [],
        file: r.filename,
        status: r.status,
        mitre: r.mitre ?? [],
        compliance: {
          pci_dss: r.pci_dss ?? [],
          gdpr: r.gdpr ?? [],
          hipaa: r.hipaa ?? [],
          nist_800_53: r.nist_800_53 ?? [],
          tsc: r.tsc ?? [],
        },
      },
    };
  },
});
