import { UpstreamError } from "../errors.js";
import { basicAuth, requestWithTimeout, statusToError, type FetchLike } from "./http.js";

/** Wazuh Server API response envelope (see the API spec: ApiResponse / AllItemsResponse*). */
export interface WazuhItems<T> {
  data: {
    affected_items: T[];
    total_affected_items: number;
    total_failed_items?: number;
    failed_items?: unknown[];
  };
  message?: string;
  error?: number;
}

export interface WazuhAgent {
  id: string;
  name?: string;
  ip?: string;
  status?: string;
  version?: string;
  lastKeepAlive?: string;
  dateAdd?: string;
  group?: string[];
  node_name?: string;
  os?: { name?: string; platform?: string; version?: string; arch?: string };
}

export interface WazuhRule {
  id: number;
  level: number;
  description: string;
  groups?: string[];
  filename?: string;
  status?: string;
  mitre?: string[];
  pci_dss?: string[];
  gdpr?: string[];
  hipaa?: string[];
  nist_800_53?: string[];
  tsc?: string[];
}

export interface WazuhManagerInfo {
  version?: string;
  type?: string;
  max_agents?: string;
  tz_name?: string;
  uuid?: string;
}

export interface WazuhApiOptions {
  url: string;
  user: string;
  password: string;
  timeoutMs: number;
  fetch: FetchLike;
  now?: () => number;
}

/** Tokens issued by the Wazuh API are valid for 900s by default; renew a bit earlier. */
const TOKEN_TTL_MS = 840_000;
const ADMINISTRATOR_ROLE_ID = 1;

export class WazuhApiClient {
  private token: string | null = null;
  private tokenIssuedAt = 0;
  private pendingAuth: Promise<string> | null = null;
  private readonly now: () => number;

  constructor(private readonly opts: WazuhApiOptions) {
    this.now = opts.now ?? Date.now;
  }

  private async authenticate(): Promise<string> {
    const res = await requestWithTimeout(
      this.opts.fetch,
      `${this.opts.url}/security/user/authenticate`,
      { method: "POST", headers: { Authorization: basicAuth(this.opts.user, this.opts.password) } },
      this.opts.timeoutMs,
      "Wazuh API",
    );
    if (!res.ok) throw statusToError(res.status, "Wazuh API", "authenticate");
    const body = (await res.json()) as { data?: { token?: string } };
    const token = body?.data?.token;
    if (!token) throw new UpstreamError("upstream_auth", "Wazuh API did not return a token");
    this.token = token;
    this.tokenIssuedAt = this.now();
    return token;
  }

  private async getToken(force = false): Promise<string> {
    const fresh = this.token && this.now() - this.tokenIssuedAt < TOKEN_TTL_MS;
    if (!force && fresh) return this.token as string;
    // de-duplicate concurrent logins
    this.pendingAuth ??= this.authenticate().finally(() => (this.pendingAuth = null));
    return this.pendingAuth;
  }

  /** GET with JWT; on 401 renews the token once and retries. */
  async get<T>(path: string, query: Record<string, string | number | undefined> = {}): Promise<T> {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== "") qs.set(k, String(v));
    const url = `${this.opts.url}${path}${qs.size ? `?${qs}` : ""}`;

    for (let attempt = 0; attempt < 2; attempt++) {
      const token = await this.getToken(attempt > 0);
      const res = await requestWithTimeout(
        this.opts.fetch,
        url,
        { method: "GET", headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } },
        this.opts.timeoutMs,
        "Wazuh API",
      );
      if (res.status === 401 && attempt === 0) {
        this.token = null;
        continue;
      }
      if (!res.ok) throw statusToError(res.status, "Wazuh API", path);
      return (await res.json()) as T;
    }
    throw new UpstreamError("upstream_auth", "Wazuh API authentication failed after token renewal");
  }

  async listAgents(params: { status?: string; platform?: string; group?: string; limit: number }) {
    return this.get<WazuhItems<WazuhAgent>>("/agents", {
      status: params.status,
      "os.platform": params.platform,
      group: params.group,
      limit: params.limit,
      sort: "+id",
      select: "id,name,ip,status,version,lastKeepAlive,os.name,os.platform,os.version,group",
    });
  }

  async getAgent(agentId: string) {
    return this.get<WazuhItems<WazuhAgent>>("/agents", { agents_list: agentId });
  }

  async getRule(ruleId: number) {
    return this.get<WazuhItems<WazuhRule>>("/rules", { rule_ids: ruleId });
  }

  async getManagerInfo() {
    return this.get<WazuhItems<WazuhManagerInfo>>("/manager/info");
  }

  /** True when the configured user holds the built-in administrator role. */
  async isAdministrator(): Promise<boolean> {
    const me = await this.get<WazuhItems<{ username?: string; roles?: number[] }>>("/security/users/me");
    const roles = me.data.affected_items[0]?.roles ?? [];
    return roles.includes(ADMINISTRATOR_ROLE_ID);
  }
}
