---
source: "common/logging-forensics.md"
title: "Security Logging & Forensics — Audit Trails, SIEM, Log Injection, GDPR"
heading: "Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [categories, checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 5/8
---

## Prevention Checklist

```
✅ LOGGING & FORENSICS CHECKLIST:
- Log ALL authentication events (login success, failure, logout, password reset)
- Log authorization failures (403 responses, ACL violations)
- Log configuration changes, privilege escalations, and admin actions
- Use structured log format (JSON, CEF, LEEF) — never plain text
- Sanitize/redact user input before writing to logs
- NEVER log passwords, tokens, secrets, or PII
- Set appropriate log levels: DEBUG=dev, INFO=normal, WARN=suspicious, ERROR=failures
- Implement log rotation and retention policies
- Use centralized logging (SIEM/SOAR) with WORM storage
- Synchronize clocks across all systems (NTP)
- Include correlation IDs to trace requests across services
- Implement audit trails for sensitive data access (who, what, when, why)
- Test your logging — simulate attacks and verify detection
- Follow GDPR: pseudonymize PII, support erasure, enforce retention limits
- Implement alerting on critical events (not just logging)
```

---