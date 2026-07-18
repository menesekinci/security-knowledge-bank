---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "6. Secure Defaults"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 20/25
---

## 6. Secure Defaults

If a default is insecure, most users will never change it. This is not a user problem — it is a design problem.

### The Secure-Defaults Checklist

| Area | Insecure Default | Secure Default |
|---|---|---|
| **Web framework** | Debug mode on, CORS `*`, session without `HttpOnly` | Debug off, CORS explicit origins, `HttpOnly+Secure+SameSite` |
| **Database** | Default admin password, network `0.0.0.0` | No default password (force on setup), listen on localhost |
| **Container** | Root user, all capabilities, writable rootfs | Non-root user, drop all caps, read-only rootfs |
| **API** | No authentication, no rate limiting | Auth required, rate limiting enabled |
| **Cloud resource** | Public bucket, open security group | Private by default, least-privilege policies |
| **Secret management** | Secrets in config files, `.env` in repo | Secrets from vault/secret manager, `.env` in `.gitignore` |
| **Logging** | Logging off, sensitive data in logs | Structured logging, PII redaction enabled |
| **TLS** | TLS disabled, allows TLS < 1.2 | TLS 1.2+ required, HSTS enabled |
| **Backup** | Unencrypted backups | Encrypted backups with separate key |
| **Dependencies** | Auto-update off, no integrity check | Dependency scanning, lock files, SBOM generation |

### Engineering Secure Defaults

- **Scaffold generators** — `npm create`, `dotnet new`, `rails new` should generate secure-by-default projects
- **Configuration validation** — the application should refuse to start with insecure settings, not run with a warning
- **Hardening guides** — if you must document a list of "things to change for production", you failed at secure defaults

---