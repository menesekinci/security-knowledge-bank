---
source: "common/logging.md"
title: "Logging & Monitoring Failures"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, logging, patterns, prevention, secure, vibe, vulnerable, what]
chunk: 3/8
---

## Why Vibe Coding Makes This Worse

- **AI doesn't generate logging code:** Focused on business logic, AI skips `logger.info()` calls for security events
- **AI logs sensitive data:** `logger.error(f"Login failed for {password}")` — leaking secrets to logs
- **No centralized logging:** AI outputs to stdout/console without structured logging
- **Missing alerting:** AI generates logs but no infrastructure for alerting on suspicious patterns
- **Verbose error handling:** AI returns stack traces in HTTP responses instead of logging them internally