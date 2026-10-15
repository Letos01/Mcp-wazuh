import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export interface AuditRecord {
  ts: string;
  caller: string;
  kind: "tool" | "resource" | "prompt" | "auth";
  name: string;
  params?: Record<string, unknown>;
  outcome: "ok" | "error" | "denied" | "rate_limited";
  result_count?: number;
  duration_ms?: number;
  injection_suspected?: boolean;
  injection_reasons?: string[];
  error_code?: string;
  ref?: string;
}

export interface AuditSink {
  write(record: AuditRecord): Promise<void>;
}

const SECRET_KEY = /pass|secret|token|authorization|api[_-]?key/i;
const MAX_PARAM_STRING = 500;

/** Defensive copy of tool params: drops anything that looks like a secret and truncates long strings. */
export function redactParams(params: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!params) return undefined;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (SECRET_KEY.test(k)) {
      out[k] = "[redacted]";
    } else if (typeof v === "string" && v.length > MAX_PARAM_STRING) {
      out[k] = v.slice(0, MAX_PARAM_STRING) + "…";
    } else {
      out[k] = v;
    }
  }
  return out;
}

/** Append-only JSONL audit log. Writes are serialized so lines never interleave. */
export class JsonlAuditSink implements AuditSink {
  private chain: Promise<void> = Promise.resolve();
  private ready: Promise<unknown>;

  constructor(
    private readonly path: string,
    private readonly onError: (e: unknown) => void = () => {},
  ) {
    this.ready = mkdir(dirname(path), { recursive: true, mode: 0o750 });
  }

  write(record: AuditRecord): Promise<void> {
    const line = JSON.stringify({ ...record, params: redactParams(record.params) }) + "\n";
    this.chain = this.chain
      .then(() => this.ready)
      .then(() => appendFile(this.path, line, { encoding: "utf8", mode: 0o640 }))
      .catch((e) => this.onError(e));
    return this.chain;
  }
}

export class MemoryAuditSink implements AuditSink {
  readonly records: AuditRecord[] = [];
  async write(record: AuditRecord): Promise<void> {
    this.records.push({ ...record, params: redactParams(record.params) });
  }
}
