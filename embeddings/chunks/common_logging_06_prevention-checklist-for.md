---
source: "common/logging.md"
title: "Logging & Monitoring Failures"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, logging, patterns, prevention, secure, vibe, vulnerable, what]
chunk: 6/8
---

## Prevention Checklist for AI Prompts

```
✅ LOGGING & MONITORING REQUIREMENTS:
- Log ALL authentication events (success, failure, password changes)
- Log authorization failures (access denied to resources)
- Log all administrative actions with actor details
- NEVER log passwords, credit cards, secrets, or session tokens
- NEVER log full request bodies or stack traces in production responses
- Use structured logging (JSON) — not plain text
- Include correlation IDs (requestId, sessionId) in every log entry
- Set up real-time alerting on security events (failed logins > 5/min)
- Implement immutable logging (write-once, append-only storage)
- Sanitize user input in log messages to prevent log injection
- Use a SIEM or log aggregation tool (ELK, Splunk, Datadog)
- Test that your alerting actually works (fire drills)
- Ensure logs have proper access controls — don't expose them publicly
```

### Monitoring Alert Thresholds

| Alert | Threshold | Severity |
|---|---|---|
| Failed logins | > 5 in 5 min from same IP | High |
| Account enumeration | > 10 different usernames from same IP | Medium |
| Brute force | > 50 failed logins in 1 hour | Critical |
| API key misuse | > 100 4xx in 5 min | High |
| Suspicious geolocation | Login from 2+ countries in 1 hour | High |
| SQL injection attempt | SQL keywords in URL params | Critical |

---