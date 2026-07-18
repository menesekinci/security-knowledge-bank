---
source: "common/logging-forensics.md"
title: "Security Logging & Forensics — Audit Trails, SIEM, Log Injection, GDPR"
heading: "Testing Your Logging"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [categories, checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 7/8
---

## Testing Your Logging

**Inject test payloads:**
```bash
# Log injection test
curl "https://app.com/login?user=%0a2024-01-01%20CRITICAL%20Access%20granted%20to%20admin"

# XSS in log viewer
curl "https://app.com/search?q=<script>alert(1)</script>"

# Sensitive data leak check
curl "https://app.com/api/error" -H "Authorization: Bearer test_token_12345"
```

**Verify log completeness:**
```bash
# Trigger various events and check logs
curl -X POST "https://app.com/login" -d "email=test&password=wrong"  # Should appear
curl "https://app.com/admin/config"  # Should log auth failure
curl "https://app.com/api/users/export"  # Should log sensitive data access
```

---