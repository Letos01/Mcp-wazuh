import { basicAuth, requestWithTimeout, statusToError, type FetchLike } from "./http.js";

export interface SearchHit<T> {
  _id: string;
  _index: string;
  _source: T;
}

export interface SearchResponse<T> {
  hits: { total?: { value: number; relation?: string } | number; hits: SearchHit<T>[] };
  aggregations?: Record<string, unknown>;
}

export interface IndexerOptions {
  url: string;
  user: string;
  password: string;
  timeoutMs: number;
  fetch: FetchLike;
}

const INDEX_PATTERN = /^[a-z0-9][a-z0-9*._-]{0,127}$/;

/**
 * Minimal OpenSearch (Wazuh Indexer) client. Only `_search` is exposed: the
 * query body is always built by this server, never supplied by the model.
 */
export class IndexerClient {
  constructor(private readonly opts: IndexerOptions) {}

  async search<T>(index: string, body: Record<string, unknown>): Promise<SearchResponse<T>> {
    if (!INDEX_PATTERN.test(index)) throw new Error(`refusing to query index pattern '${index}'`);
    const res = await requestWithTimeout(
      this.opts.fetch,
      `${this.opts.url}/${encodeURIComponent(index).replace(/%2A/g, "*")}/_search`,
      {
        method: "POST",
        headers: {
          Authorization: basicAuth(this.opts.user, this.opts.password),
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
      },
      this.opts.timeoutMs,
      "Wazuh Indexer",
    );
    if (!res.ok) throw statusToError(res.status, "Wazuh Indexer", index);
    return (await res.json()) as SearchResponse<T>;
  }
}

export function totalHits(r: SearchResponse<unknown>): number {
  const t = r.hits.total;
  if (typeof t === "number") return t;
  return t?.value ?? r.hits.hits.length;
}
