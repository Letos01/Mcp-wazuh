/**
 * Heuristic prompt-injection detector.
 *
 * This is a tripwire, not a guarantee: it flags (never blocks) content that
 * looks like instructions aimed at the model, so the agent and the analyst can
 * see it and the audit log records it. The real defense is the untrusted-data
 * envelope plus read-only tools.
 */
export interface InjectionFinding {
  suspected: boolean;
  reasons: string[];
  where?: string;
}

interface Rule {
  id: string;
  re: RegExp;
}

const RULES: Rule[] = [
  // English
  {
    id: "override_instructions",
    re: /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|directives?|guidelines?)\b/i,
  },
  {
    id: "role_reassignment",
    re: /\b(you are now|from now on,? you|act as (an?|the) |pretend (to be|you are)|new (instructions|role|persona)\s*:)/i,
  },
  { id: "system_prompt_reference", re: /\b(system prompt|developer (message|mode)|jailbreak|DAN mode)\b/i },
  {
    id: "exfiltration_request",
    re: /\b(reveal|print|show|send|exfiltrate|leak|output)\b[^.\n]{0,40}\b(system prompt|api[_ -]?keys?|credentials?|passwords?|tokens?|secrets?)\b/i,
  },
  {
    id: "agent_directive",
    re: /\b(assistant|ai|claude|gpt|llm|agent|model)\b\s*[,:]\s*(please\s+)?(ignore|run|execute|call|delete|disable|close|mark|send|stop)\b/i,
  },
  // Portuguese / Spanish
  {
    id: "override_instructions_pt",
    re: /(?<![\p{L}])(ignore|ignora|desconsidere|desconsidera|esque[çc]a|ignorar)(?![\p{L}])[^.\n]{0,40}(?<![\p{L}])(instru[çc][õo]es|instrucciones|regras|reglas|comandos)(?![\p{L}])/iu,
  },
  {
    id: "role_reassignment_pt",
    re: /(?<![\p{L}])(voc[êe] agora [ée]|a partir de agora,? voc[êe]|ahora eres|finja ser|aja como)(?![\p{L}])/iu,
  },
  // Chat-template / tool-call forgery
  {
    id: "chat_template_token",
    re: /(<\|im_(start|end)\|>|<\|(system|user|assistant|endoftext)\|>|\[\/?INST\]|<<\/?SYS>>|^\s*###\s*(system|instruction)s?\b)/im,
  },
  { id: "role_marker", re: /(^|\n)\s*(system|assistant|human|user)\s*:\s*\S/i },
  // Set by the sanitizer when it decodes invisible Unicode tag characters: hiding text is itself the signal.
  { id: "hidden_unicode_text", re: /\[hidden-unicode-text: / },
  {
    id: "tool_call_forgery",
    re: /(<\/?(function_calls|invoke|tool_call|tool_use|antml:[a-z_]+)\b|"(tool_use|function_call|tool_calls)"\s*:|"name"\s*:\s*"[a-z_]{3,}"\s*,\s*"(arguments|input|parameters)"\s*:)/i,
  },
];

const BASE64_CANDIDATE = /[A-Za-z0-9+/]{32,}={0,2}/g;
const MAX_B64_CANDIDATES = 10;

function matchRules(text: string): string[] {
  return RULES.filter((r) => r.re.test(text)).map((r) => r.id);
}

function decodeBase64Printable(s: string): string | null {
  try {
    const decoded = Buffer.from(s, "base64").toString("utf8");
    // keep only mostly-printable decodes (avoid binary noise)
    const printable = decoded.replace(/[^\x20-\x7E\u00A0-\u024F\n\t]/g, "");
    return printable.length >= decoded.length * 0.9 ? decoded : null;
  } catch {
    return null;
  }
}

export function detectInjection(text: string): InjectionFinding {
  if (!text) return { suspected: false, reasons: [] };
  const reasons = new Set(matchRules(text));

  const candidates = text.match(BASE64_CANDIDATE)?.slice(0, MAX_B64_CANDIDATES) ?? [];
  for (const c of candidates) {
    const decoded = decodeBase64Printable(c);
    if (decoded) {
      for (const id of matchRules(decoded)) reasons.add(`base64:${id}`);
    }
  }
  return { suspected: reasons.size > 0, reasons: [...reasons] };
}
