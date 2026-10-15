/**
 * Output sanitization for attacker-controlled data.
 *
 * Wazuh alerts carry raw log lines, URLs, user agents, command lines and other
 * fields that an attacker can fully control. Everything that comes from a log is
 * treated as untrusted DATA and is:
 *   1. normalized (NFKC) and stripped of ANSI/OSC escapes, control, bidi and zero-width characters;
 *   2. truncated to a maximum length;
 *   3. defanged so it cannot close or forge the <untrusted_data> wrapper;
 *   4. scanned by a heuristic prompt-injection detector;
 *   5. returned inside an <untrusted_data> envelope.
 */
import { detectInjection, type InjectionFinding } from "./injection.js";

export const WRAPPER_TAG = "untrusted_data";

const ANSI_CSI = /\u001b\[[0-?]*[ -/]*[@-~]/g;
const ANSI_OSC = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g;
const ANSI_OTHER = /\u001b[@-Z\\-_]/g;
// C0 controls except \t \n \r, DEL and C1 controls
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// Bidi overrides/isolates and zero-width characters (used to hide or reorder text)
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;
// Any attempt to open/close/forge the wrapper tag, tolerant to spacing and case
const WRAPPER_FORGERY = /<\s*\/?\s*untrusted[\s_-]*data\b[^>]*>?/gi;

export const TRUNCATION_MARKER = "…[truncated]";

export function cleanText(input: unknown, maxLength: number): string {
  if (input === null || input === undefined) return "";
  let s = typeof input === "string" ? input : safeStringify(input);
  s = s.normalize("NFKC");
  s = s.replace(ANSI_OSC, "").replace(ANSI_CSI, "").replace(ANSI_OTHER, "");
  s = s.replace(CONTROL, "").replace(INVISIBLE, "");
  s = s.replace(WRAPPER_FORGERY, "[removed-wrapper-tag]");
  if (s.length > maxLength) s = s.slice(0, maxLength) + TRUNCATION_MARKER;
  return s;
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function escapeAttr(v: string): string {
  return v.replace(/[^A-Za-z0-9._:-]/g, "_").slice(0, 64);
}

/**
 * Collects untrusted values produced while building one tool result, so the
 * result (and the audit log) can report whether any of them looked like a
 * prompt-injection attempt.
 */
export class UntrustedCollector {
  readonly findings: InjectionFinding[] = [];

  constructor(private readonly maxLength: number) {}

  get injectionSuspected(): boolean {
    return this.findings.length > 0;
  }

  get reasons(): string[] {
    return [...new Set(this.findings.flatMap((f) => f.reasons))];
  }

  /** Log-derived content: cleaned, scanned and wrapped in the untrusted envelope. */
  wrap(value: unknown, source: string, id: string, maxLength = this.maxLength): string {
    const text = cleanText(value, maxLength);
    this.scan(text, `${source}:${id}`);
    return `<${WRAPPER_TAG} source='${escapeAttr(source)}' id='${escapeAttr(id)}'>\n${text}\n</${WRAPPER_TAG}>`;
  }

  /**
   * Short metadata that is still attacker-influenced (agent names, rule
   * descriptions with dynamic fields): cleaned and scanned, not wrapped.
   */
  field(value: unknown, where: string, maxLength = 256): string {
    const text = cleanText(value, maxLength);
    this.scan(text, where);
    return text;
  }

  private scan(text: string, where: string): void {
    const f = detectInjection(text);
    if (f.suspected) this.findings.push({ ...f, where });
  }
}
