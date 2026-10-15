import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMcpServer, type ServerDeps } from "../server.js";

/** Local mode (Claude Desktop / Claude Code): the parent process is the only caller. */
export async function startStdio(deps: ServerDeps): Promise<void> {
  const server = createMcpServer(deps, "stdio");
  await server.connect(new StdioServerTransport());
  deps.logger.info("mcp-wazuh listening on stdio");
}
