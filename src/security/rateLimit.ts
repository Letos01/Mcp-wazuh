// Idle keys are dropped once the map grows past this, so per-IP keys (failed auth) stay bounded.
const MAX_KEYS = 10_000;

/** Sliding-window rate limiter keyed by caller (token hash, "stdio", or client IP for failed auth). */
export class RateLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(
    private readonly limit: number,
    private readonly windowMs = 60_000,
    private readonly now: () => number = Date.now,
  ) {}

  /** Returns true when the call is allowed (and records it). */
  take(key: string): boolean {
    const t = this.now();
    const cutoff = t - this.windowMs;
    if (this.hits.size > MAX_KEYS) this.prune(cutoff);
    const list = (this.hits.get(key) ?? []).filter((x) => x > cutoff);
    if (list.length >= this.limit) {
      this.hits.set(key, list);
      return false;
    }
    list.push(t);
    this.hits.set(key, list);
    return true;
  }

  private prune(cutoff: number): void {
    for (const [k, list] of this.hits) if (!list.some((x) => x > cutoff)) this.hits.delete(k);
  }

  /** Seconds until the next call would be allowed. */
  retryAfter(key: string): number {
    const list = this.hits.get(key);
    if (!list || list.length === 0) return 0;
    return Math.max(0, Math.ceil((list[0] + this.windowMs - this.now()) / 1000));
  }
}
