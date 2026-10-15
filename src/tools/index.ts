import { getAgent, listAgents } from "./agents.js";
import { alertStats, getAlert, searchAlerts } from "./alerts.js";
import { getRule } from "./rules.js";
import type { ToolDefinition } from "./types.js";
import { listVulnerabilities } from "./vulnerabilities.js";

export const TOOLS: ToolDefinition[] = [
  searchAlerts,
  getAlert,
  alertStats,
  listAgents,
  getAgent,
  getRule,
  listVulnerabilities,
] as unknown as ToolDefinition[];
