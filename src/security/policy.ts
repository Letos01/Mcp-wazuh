import { ToolInputError } from "../errors.js";

export interface TimeRange {
  from: string;
  to: string;
}

const DAY_MS = 86_400_000;
const DEFAULT_LOOKBACK_MS = DAY_MS;

/**
 * Resolves and bounds the query window. Defaults to the last 24h, never lets a
 * single query span more than `maxDays`, and rejects inverted ranges.
 */
export function resolveTimeRange(
  from: string | undefined,
  to: string | undefined,
  maxDays: number,
  now: Date = new Date(),
): TimeRange {
  const toDate = to ? new Date(to) : now;
  const fromDate = from ? new Date(from) : new Date(toDate.getTime() - DEFAULT_LOOKBACK_MS);
  if (Number.isNaN(toDate.getTime()) || Number.isNaN(fromDate.getTime())) {
    throw new ToolInputError("time_from/time_to must be ISO 8601 timestamps");
  }
  if (fromDate >= toDate) {
    throw new ToolInputError("time_from must be earlier than time_to");
  }
  if (toDate.getTime() - fromDate.getTime() > maxDays * DAY_MS) {
    throw new ToolInputError(`the time window cannot exceed ${maxDays} days`);
  }
  return { from: fromDate.toISOString(), to: toDate.toISOString() };
}

export function clampLimit(requested: number | undefined, fallback: number, max: number): number {
  const v = requested ?? fallback;
  return Math.max(1, Math.min(v, max));
}
