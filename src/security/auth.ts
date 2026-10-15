import { createHash, timingSafeEqual } from "node:crypto";

function sha256(v: string): Buffer {
  return createHash("sha256").update(v, "utf8").digest();
}

/** Short, non-reversible identifier for a token, safe to put in logs. */
export function callerIdForToken(token: string): string {
  return "tok_" + sha256(token).toString("hex").slice(0, 12);
}

/**
 * Bearer-token verifier. Tokens are compared as SHA-256 digests with
 * timingSafeEqual (equal length, constant time), and every configured token is
 * checked so the loop does not leak which one matched.
 */
export class BearerAuth {
  private readonly digests: Buffer[];

  constructor(tokens: string[]) {
    this.digests = tokens.map(sha256);
  }

  /** Returns the caller id when the Authorization header is valid, otherwise null. */
  verify(authorizationHeader: string | undefined): string | null {
    if (!authorizationHeader) return null;
    const m = /^Bearer\s+(\S{1,512})$/i.exec(authorizationHeader.trim());
    if (!m) return null;
    const candidate = sha256(m[1]);
    let ok = false;
    for (const d of this.digests) {
      if (timingSafeEqual(d, candidate)) ok = true;
    }
    return ok ? callerIdForToken(m[1]) : null;
  }
}
