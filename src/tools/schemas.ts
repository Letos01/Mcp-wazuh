import { z } from "zod";

/** Strict identifiers: nothing the model sends is ever interpolated into a query unvalidated. */
export const agentId = z
  .string()
  .regex(/^\d{3,6}$/, "agent_id must be the numeric Wazuh agent id, e.g. '001'")
  .describe("Wazuh agent id, e.g. '001'");

export const agentName = z
  .string()
  .regex(/^[A-Za-z0-9._-]{1,64}$/, "agent_name may contain letters, digits, '.', '_' and '-' only")
  .describe("Exact agent name");

export const ruleId = z.coerce.number().int().min(1).max(999_999).describe("Wazuh rule id, e.g. 5710");

export const alertId = z
  .string()
  .regex(/^\d{9,11}\.\d{1,15}$/, "alert_id must look like '1729000000.123456'")
  .describe("Wazuh alert id (the alert's `id` field, e.g. '1729000000.123456')");

export const mitreTechnique = z
  .string()
  .regex(/^T\d{4}(\.\d{3})?$/, "mitre_technique must look like T1059 or T1059.001")
  .describe("MITRE ATT&CK technique id, e.g. T1110 or T1059.001");

export const isoTime = z.iso.datetime({ offset: true });

export const timeFrom = isoTime
  .optional()
  .describe("Start (ISO 8601, e.g. 2026-10-14T00:00:00Z). Default: 24h before time_to");
export const timeTo = isoTime.optional().describe("End (ISO 8601). Default: now");

export const limit = z.number().int().min(1).max(500).optional().describe("Max results (capped by server policy)");

export const freeText = z
  .string()
  .min(2)
  .max(200)
  .describe("Literal text to look for in the log and rule description (no query operators)");

export const severity = z.enum(["Critical", "High", "Medium", "Low"]);
export const agentStatus = z.enum(["active", "disconnected", "never_connected", "pending"]);
export const osPlatform = z
  .string()
  .regex(/^[a-z0-9_]{1,32}$/)
  .describe("os.platform value, e.g. ubuntu, windows, darwin, centos");
export const group = z
  .string()
  .regex(/^[A-Za-z0-9._-]{1,64}$/)
  .describe("Agent group name");
