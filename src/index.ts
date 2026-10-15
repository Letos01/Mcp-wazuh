#!/usr/bin/env node
import { pino } from "pino";
import { createFetch } from "./clients/http.js";
import { IndexerClient } from "./clients/indexer.js";
import { WazuhApiClient } from "./clients/wazuhApi.js";
import { ConfigError, loadConfig } from "./config.js";
import { JsonlAuditSink } from "./security/audit.js";
import { RateLimiter } from "./security/rateLimit.js";
import type { ServerDeps } from "./server.js";
import { startHttp } from "./transports/http.js";
import { startStdio } from "./transports/stdio.js";

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(`${e.message}\n`);
      process.exit(2);
    }
    throw e;
  }

  // stdout is reserved for the MCP protocol in stdio mode: logs always go to stderr.
  const logger = pino(
    {
      level: config.logLevel,
      redact: { paths: ["*.password", "*.token", "*.authorization", "headers.authorization"], censor: "[redacted]" },
    },
    pino.destination(2),
  );

  if (config.tls.insecure) {
    logger.warn("TLS_INSECURE=true: certificate validation is DISABLED. Use only in a lab.");
  }

  const fetchImpl = createFetch(config.tls);
  const api = new WazuhApiClient({ ...config.wazuhApi, timeoutMs: config.limits.requestTimeoutMs, fetch: fetchImpl });
  const indexer = new IndexerClient({ ...config.indexer, timeoutMs: config.limits.requestTimeoutMs, fetch: fetchImpl });

  const deps: ServerDeps = {
    api,
    indexer,
    config,
    audit: new JsonlAuditSink(config.auditLogPath, (e) => logger.error({ err: e }, "audit write failed")),
    rateLimiter: new RateLimiter(config.limits.rateLimitPerMinute),
    logger,
  };

  // Least-privilege check: warn loudly if the API user is an administrator.
  api
    .isAdministrator()
    .then((admin) => {
      if (admin) {
        logger.warn(
          "The Wazuh API user has the 'administrator' role. mcp-wazuh only needs read access: " +
            "use a dedicated user with the 'readonly' role (see README).",
        );
      }
    })
    .catch((e) => logger.warn({ err: e }, "could not verify Wazuh API user roles"));

  if (config.transport === "http") await startHttp(deps);
  else await startStdio(deps);
}

main().catch((e) => {
  process.stderr.write(`fatal: ${(e as Error).message}\n`);
  process.exit(1);
});
