import { z } from "zod";

const bool = z.enum(["true", "false", "1", "0"]).transform((v) => v === "true" || v === "1");

const ConfigSchema = z
  .object({
    WAZUH_API_URL: z.url(),
    WAZUH_API_USER: z.string().min(1),
    WAZUH_API_PASSWORD: z.string().min(1),
    WAZUH_INDEXER_URL: z.url(),
    WAZUH_INDEXER_USER: z.string().min(1),
    WAZUH_INDEXER_PASSWORD: z.string().min(1),
    WAZUH_ALERTS_INDEX: z.string().default("wazuh-alerts-*"),
    WAZUH_VULN_INDEX: z.string().default("wazuh-states-vulnerabilities-*"),
    TLS_CA_PATH: z.string().optional(),
    TLS_INSECURE: bool.default(false),
    MCP_TRANSPORT: z.enum(["stdio", "http"]).default("stdio"),
    MCP_HTTP_HOST: z.string().default("127.0.0.1"),
    MCP_HTTP_PORT: z.coerce.number().int().min(1).max(65535).default(8080),
    MCP_AUTH_TOKENS: z.string().optional(),
    MCP_ALLOWED_ORIGINS: z.string().optional(),
    MAX_RESULTS: z.coerce.number().int().min(1).max(500).default(50),
    MAX_TIME_WINDOW_DAYS: z.coerce.number().int().min(1).max(365).default(30),
    MAX_FIELD_LENGTH: z.coerce.number().int().min(100).max(20000).default(2000),
    RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).max(10000).default(60),
    REQUEST_TIMEOUT_MS: z.coerce.number().int().min(1000).max(120000).default(15000),
    AUDIT_LOG_PATH: z.string().default("./audit/audit.jsonl"),
    LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),
  })
  .superRefine((c, ctx) => {
    if (c.MCP_TRANSPORT === "http") {
      const tokens = parseTokens(c.MCP_AUTH_TOKENS);
      if (tokens.length === 0) {
        ctx.addIssue({
          code: "custom",
          path: ["MCP_AUTH_TOKENS"],
          message: "required when MCP_TRANSPORT=http (comma-separated list)",
        });
      }
      if (tokens.some((t) => t.length < 32)) {
        ctx.addIssue({
          code: "custom",
          path: ["MCP_AUTH_TOKENS"],
          message: "each token must have at least 32 characters",
        });
      }
    }
  });

export type RawConfig = z.infer<typeof ConfigSchema>;

export interface Config {
  wazuhApi: { url: string; user: string; password: string };
  indexer: { url: string; user: string; password: string; alertsIndex: string; vulnIndex: string };
  tls: { caPath?: string; insecure: boolean };
  transport: "stdio" | "http";
  http: { host: string; port: number; authTokens: string[]; allowedOrigins: string[] };
  limits: {
    maxResults: number;
    maxTimeWindowDays: number;
    maxFieldLength: number;
    rateLimitPerMinute: number;
    requestTimeoutMs: number;
  };
  auditLogPath: string;
  logLevel: RawConfig["LOG_LEVEL"];
}

export function parseTokens(raw?: string): string[] {
  return (raw ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

export class ConfigError extends Error {}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = ConfigSchema.safeParse(env);
  if (!parsed.success) {
    // Never echo values: only variable names and the reason.
    const lines = parsed.error.issues.map((i) => `  - ${i.path.join(".")}: ${i.message}`);
    throw new ConfigError(`Invalid configuration:\n${lines.join("\n")}`);
  }
  const c = parsed.data;
  return {
    wazuhApi: { url: stripSlash(c.WAZUH_API_URL), user: c.WAZUH_API_USER, password: c.WAZUH_API_PASSWORD },
    indexer: {
      url: stripSlash(c.WAZUH_INDEXER_URL),
      user: c.WAZUH_INDEXER_USER,
      password: c.WAZUH_INDEXER_PASSWORD,
      alertsIndex: c.WAZUH_ALERTS_INDEX,
      vulnIndex: c.WAZUH_VULN_INDEX,
    },
    tls: { caPath: c.TLS_CA_PATH, insecure: c.TLS_INSECURE },
    transport: c.MCP_TRANSPORT,
    http: {
      host: c.MCP_HTTP_HOST,
      port: c.MCP_HTTP_PORT,
      authTokens: parseTokens(c.MCP_AUTH_TOKENS),
      allowedOrigins: parseTokens(c.MCP_ALLOWED_ORIGINS),
    },
    limits: {
      maxResults: c.MAX_RESULTS,
      maxTimeWindowDays: c.MAX_TIME_WINDOW_DAYS,
      maxFieldLength: c.MAX_FIELD_LENGTH,
      rateLimitPerMinute: c.RATE_LIMIT_PER_MINUTE,
      requestTimeoutMs: c.REQUEST_TIMEOUT_MS,
    },
    auditLogPath: c.AUDIT_LOG_PATH,
    logLevel: c.LOG_LEVEL,
  };
}

function stripSlash(u: string): string {
  return u.replace(/\/+$/, "");
}
