import { readFileSync } from "node:fs";
import { Agent, fetch as undiciFetch } from "undici";
import { UpstreamError } from "../errors.js";

export interface FetchInit {
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
}

export interface FetchResponse {
  status: number;
  ok: boolean;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export type FetchLike = (url: string, init: FetchInit) => Promise<FetchResponse>;

export interface TlsOptions {
  caPath?: string;
  insecure: boolean;
}

/** fetch bound to a TLS-validating dispatcher (custom CA supported). */
export function createFetch(tls: TlsOptions): FetchLike {
  const dispatcher = new Agent({
    connect: {
      ca: tls.caPath ? readFileSync(tls.caPath) : undefined,
      rejectUnauthorized: !tls.insecure,
    },
  });
  // redirect: "error": credentials travel in headers, so a redirect is refused rather than followed.
  return (url, init) => undiciFetch(url, { ...init, dispatcher, redirect: "error" }) as Promise<FetchResponse>;
}

export function basicAuth(user: string, password: string): string {
  return "Basic " + Buffer.from(`${user}:${password}`, "utf8").toString("base64");
}

/** Runs a request with a timeout and maps transport failures to UpstreamError. */
export async function requestWithTimeout(
  fetchImpl: FetchLike,
  url: string,
  init: Omit<FetchInit, "signal">,
  timeoutMs: number,
  service: string,
): Promise<FetchResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } catch (e) {
    if (controller.signal.aborted) {
      throw new UpstreamError("upstream_timeout", `${service} request timed out after ${timeoutMs}ms`);
    }
    throw new UpstreamError("upstream_error", `${service} request failed: ${(e as Error).message}`);
  } finally {
    clearTimeout(timer);
  }
}

export function statusToError(status: number, service: string, detail: string): UpstreamError {
  if (status === 401) return new UpstreamError("upstream_auth", `${service} authentication failed`, status);
  if (status === 403)
    return new UpstreamError("upstream_forbidden", `${service} denied the request: ${detail}`, status);
  if (status === 404)
    return new UpstreamError("upstream_not_found", `${service} resource not found: ${detail}`, status);
  return new UpstreamError("upstream_error", `${service} returned HTTP ${status}: ${detail}`, status);
}
