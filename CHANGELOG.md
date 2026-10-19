# Changelog

## 1.1.0

Security hardening from a pre-publication review:

- Invisible Unicode tag characters (U+E0000-E007F, "ASCII smuggling") were passed through the sanitizer
  unchanged and not flagged. They are now decoded into a visible `[hidden-unicode-text: …]` marker, scanned,
  and flagged as `hidden_unicode_text`. More invisible characters are stripped (soft hyphen, Hangul fillers,
  variation selectors, combining grapheme joiner).
- HTTP mode: failed authentication is rate-limited per client IP (429 after 20/min) and no longer audited past
  the limit, so a client without a token cannot flood the audit log.
- HTTP mode: the `Origin` header is validated against `MCP_ALLOWED_ORIGINS` (DNS-rebinding protection, as the MCP
  spec requires). Requests without `Origin` (non-browser clients) are unaffected.
- Upstream requests to the Wazuh API and Indexer no longer follow redirects, since credentials travel in headers.

## 1.0.0

- Seven read-only tools: `search_alerts`, `get_alert`, `alert_stats`, `list_agents`, `get_agent`, `get_rule`,
  `list_vulnerabilities`; resource `wazuh://manager/info`; prompt `triage_alert`.
- Untrusted-data envelope, sanitizer and prompt-injection tripwire (EN/PT patterns, base64 rescan).
- Server-built queries from strict schemas; result and time-window caps; rate limiting; JSONL audit log.
- stdio and Streamable HTTP (Bearer) transports.
- One-command Wazuh 4.14 lab with end-to-end tests.
- SCA compliance findings excluded from alert tools by default.
- Requires Node 22.12+.
