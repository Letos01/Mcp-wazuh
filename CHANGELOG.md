# Changelog

## 1.0.0

- Seven read-only tools: `search_alerts`, `get_alert`, `alert_stats`, `list_agents`, `get_agent`, `get_rule`,
  `list_vulnerabilities`; resource `wazuh://manager/info`; prompt `triage_alert`.
- Untrusted-data envelope, sanitizer and prompt-injection tripwire (EN/PT patterns, base64 rescan).
- Server-built queries from strict schemas; result and time-window caps; rate limiting; JSONL audit log.
- stdio and Streamable HTTP (Bearer) transports.
- One-command Wazuh 4.14 lab with end-to-end tests.
- SCA compliance findings excluded from alert tools by default.
- Requires Node 22.12+.
