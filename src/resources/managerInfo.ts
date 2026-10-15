import type { WazuhApiClient } from "../clients/wazuhApi.js";

export async function readManagerInfo(api: WazuhApiClient) {
  const res = await api.getManagerInfo();
  const info = res.data.affected_items[0] ?? {};
  return {
    version: info.version,
    type: info.type,
    max_agents: info.max_agents,
    timezone: info.tz_name,
    uuid: info.uuid,
  };
}
