---
source: "common/misconfiguration.md"
title: "Security Misconfiguration"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, fixed, headers, misconfigurations, security, vibe, what]
chunk: 7/9
---

## Prevention Checklist for AI Prompts

```
✅ CONFIGURATION REQUIREMENTS:
- Use environment variables for ALL secrets and config values
- Never hardcode credentials, even in sample code or comments
- Set NODE_ENV=production / DEBUG=False / APP_ENV=production
- Enable all security middleware (Helmet, Django security middleware)
- Configure CORS with explicit allowlist, never wildcard
- Validate file uploads by content type (not extension)
- Remove default accounts or change credentials immediately
- Disable unnecessary HTTP methods (TRACE, PUT, DELETE if unused)
- Set restrictive security headers
- Use HTTPS only with HSTS
- Keep software/frameworks updated
- Scan infrastructure with tools like ScoutSuite (cloud) or Lynis (Linux)
```

---