import { describe, expect, it } from "vitest";
import type { FetchLike } from "../../src/clients/http.js";
import { IndexerClient } from "../../src/clients/indexer.js";
import { WazuhApiClient } from "../../src/clients/wazuhApi.js";
import { UpstreamError } from "../../src/errors.js";
import { API, IDX, authRoute, fakeFetch, items } from "../helpers.js";

function apiClient(fetchImpl: FetchLike, now?: () => number) {
  return new WazuhApiClient({ url: API, user: "u", password: "p", timeoutMs: 200, fetch: fetchImpl, now });
}

describe("WazuhApiClient", () => {
  it("authenticates with Basic auth and reuses the JWT", async () => {
    const { fetchImpl, calls } = fakeFetch({
      "POST /security/user/authenticate": authRoute,
      "GET /rules": () => ({ json: items([{ id: 5710, level: 5, description: "x" }]) }),
    });
    const api = apiClient(fetchImpl);
    await api.getRule(5710);
    await api.getRule(5710);
    const auths = calls.filter((c) => c.url.endsWith("/security/user/authenticate"));
    expect(auths).toHaveLength(1);
    expect(auths[0].init.headers.Authorization).toBe("Basic " + Buffer.from("u:p").toString("base64"));
    const get = calls.find((c) => c.url.includes("/rules"))!;
    expect(get.init.headers.Authorization).toBe("Bearer jwt-1");
    expect(get.url).toBe(`${API}/rules?rule_ids=5710`);
  });

  it("renews the token once on 401 and retries", async () => {
    let n = 0;
    let gets = 0;
    const { fetchImpl } = fakeFetch({
      "POST /security/user/authenticate": () => ({ json: { data: { token: `jwt-${++n}` } } }),
      "GET /agents": (r) => {
        gets++;
        return r.init.headers.Authorization === "Bearer jwt-1" ? { status: 401 } : { json: items([{ id: "001" }]) };
      },
    });
    const res = await apiClient(fetchImpl).getAgent("001");
    expect(res.data.affected_items[0].id).toBe("001");
    expect(n).toBe(2);
    expect(gets).toBe(2);
  });

  it("gives up after a second 401", async () => {
    const { fetchImpl } = fakeFetch({
      "POST /security/user/authenticate": authRoute,
      "GET /agents": () => ({ status: 401 }),
    });
    await expect(apiClient(fetchImpl).getAgent("001")).rejects.toMatchObject({ code: "upstream_auth" });
  });

  it("proactively renews an expired token", async () => {
    let t = 0;
    let n = 0;
    const { fetchImpl } = fakeFetch({
      "POST /security/user/authenticate": () => ({ json: { data: { token: `jwt-${++n}` } } }),
      "GET /manager/info": () => ({ json: items([{ version: "v4.14.0" }]) }),
    });
    const api = apiClient(fetchImpl, () => t);
    await api.getManagerInfo();
    t = 900_000;
    await api.getManagerInfo();
    expect(n).toBe(2);
  });

  it("deduplicates concurrent logins", async () => {
    let n = 0;
    const { fetchImpl } = fakeFetch({
      "POST /security/user/authenticate": () => ({ json: { data: { token: `jwt-${++n}` } }, delayMs: 20 }),
      "GET /rules": () => ({ json: items([]) }),
    });
    const api = apiClient(fetchImpl);
    await Promise.all([api.getRule(1), api.getRule(2), api.getRule(3)]);
    expect(n).toBe(1);
  });

  it("maps timeouts and HTTP errors to UpstreamError", async () => {
    const slow = fakeFetch({
      "POST /security/user/authenticate": authRoute,
      "GET /rules": () => ({ json: items([]), delayMs: 1000 }),
    });
    await expect(apiClient(slow.fetchImpl).getRule(1)).rejects.toMatchObject({ code: "upstream_timeout" });

    const forbidden = fakeFetch({
      "POST /security/user/authenticate": authRoute,
      "GET /rules": () => ({ status: 403 }),
    });
    await expect(apiClient(forbidden.fetchImpl).getRule(1)).rejects.toMatchObject({ code: "upstream_forbidden" });

    const badLogin = fakeFetch({ "POST /security/user/authenticate": () => ({ status: 401 }) });
    await expect(apiClient(badLogin.fetchImpl).getRule(1)).rejects.toBeInstanceOf(UpstreamError);
  });

  it("detects the administrator role", async () => {
    const { fetchImpl } = fakeFetch({
      "POST /security/user/authenticate": authRoute,
      "GET /security/users/me": () => ({ json: items([{ username: "wazuh", roles: [1] }]) }),
    });
    expect(await apiClient(fetchImpl).isAdministrator()).toBe(true);
  });
});

describe("IndexerClient", () => {
  it("POSTs a JSON body to _search with Basic auth", async () => {
    const { fetchImpl, calls } = fakeFetch({
      "POST /wazuh-alerts-*/_search": () => ({ json: { hits: { hits: [] } } }),
    });
    const idx = new IndexerClient({ url: IDX, user: "r", password: "p", timeoutMs: 200, fetch: fetchImpl });
    await idx.search("wazuh-alerts-*", { size: 1 });
    expect(calls[0].url).toBe(`${IDX}/wazuh-alerts-*/_search`);
    expect(calls[0].body).toEqual({ size: 1 });
    expect(calls[0].init.headers.Authorization).toMatch(/^Basic /);
  });

  it("refuses suspicious index patterns", async () => {
    const { fetchImpl } = fakeFetch({});
    const idx = new IndexerClient({ url: IDX, user: "r", password: "p", timeoutMs: 200, fetch: fetchImpl });
    await expect(idx.search("../_cluster/settings", {})).rejects.toThrow(/refusing/);
    await expect(idx.search("_all", {})).rejects.toThrow(/refusing/);
  });
});
