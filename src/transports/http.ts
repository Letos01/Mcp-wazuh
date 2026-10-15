import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { BearerAuth } from "../security/auth.js";
import { createMcpServer, type ServerDeps } from "../server.js";

const MAX_BODY_BYTES = 256 * 1024;
const MCP_PATH = "/mcp";

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new Error("payload_too_large");
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : undefined;
}

/**
 * Remote mode: Streamable HTTP, stateless (one MCP server instance per request),
 * Bearer token required on every request, bound to 127.0.0.1 unless configured otherwise.
 */
export function createHttpApp(deps: ServerDeps): Server {
  const auth = new BearerAuth(deps.config.http.authTokens);

  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");

    if (url.pathname === "/healthz" && req.method === "GET") {
      return sendJson(res, 200, { status: "ok" });
    }
    if (url.pathname !== MCP_PATH) return sendJson(res, 404, { error: "not_found" });

    const caller = auth.verify(req.headers.authorization);
    if (!caller) {
      await deps.audit.write({
        ts: new Date().toISOString(),
        caller: `ip:${req.socket.remoteAddress ?? "unknown"}`,
        kind: "auth",
        name: `${req.method} ${MCP_PATH}`,
        outcome: "denied",
      });
      return sendJson(res, 401, { error: "unauthorized" }, { "WWW-Authenticate": 'Bearer realm="mcp-wazuh"' });
    }

    if (req.method !== "POST") {
      // Stateless server: no SSE stream or session to resume/delete.
      return sendJson(res, 405, { error: "method_not_allowed" }, { Allow: "POST" });
    }

    let body: unknown;
    try {
      body = await readBody(req);
    } catch (e) {
      const tooLarge = (e as Error).message === "payload_too_large";
      return sendJson(res, tooLarge ? 413 : 400, { error: tooLarge ? "payload_too_large" : "invalid_json" });
    }

    const server = createMcpServer(deps, caller);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (e) {
      deps.logger.error({ err: e }, "http request failed");
      if (!res.headersSent) sendJson(res, 500, { error: "internal_error" });
    }
  });
}

export async function startHttp(deps: ServerDeps): Promise<Server> {
  const app = createHttpApp(deps);
  const { host, port } = deps.config.http;
  await new Promise<void>((resolve) => app.listen(port, host, resolve));
  if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
    deps.logger.warn({ host }, "HTTP transport bound to a non-loopback address: put it behind TLS (reverse proxy)");
  }
  deps.logger.info({ host, port, path: MCP_PATH }, "mcp-wazuh listening on Streamable HTTP");
  return app;
}
