---
source: "common/logging-forensics.md"
title: "Security Logging & Forensics — Audit Trails, SIEM, Log Injection, GDPR"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [categories, checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 3/8
---

## Why Vibe Coding Makes This Worse

- **AI doesn't add logging unless told** — Logging is "non-functional overhead" that AI skips.
- **AI logs sensitive data** — Passwords, tokens, PII end up in logs because AI doesn't audit log content.
- **AI produces unstructured logs** — Raw strings without standardized format (JSON/CEF/LEEF).
- **AI doesn't handle log injection** — User input is concatenated into log strings unsanitized.
- **AI ignores SIEM integration** — Logs written to stdout only, no centralized collection.

---