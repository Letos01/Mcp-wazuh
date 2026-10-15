# Security policy

mcp-wazuh is a security tool, so reports are welcome.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository
(https://github.com/Letos01/Mcp-wazuh/security/advisories/new). Please do not open a public issue.

Useful reports include: a way to make the server write to Wazuh, a bypass of the sanitizer or the
`<untrusted_data>` envelope, a query-injection path, auth or rate-limit bypass in HTTP mode, or secrets in logs.

You can expect an acknowledgement within a few days. This is a personal project, so there is no formal SLA.

## Supported versions

Only the latest release on `main`.

## Scope

See [docs/threat-model.md](docs/threat-model.md) for what is and is not in scope.
