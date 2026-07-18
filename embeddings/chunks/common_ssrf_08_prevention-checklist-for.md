---
source: "common/ssrf.md"
title: "Server-Side Request Forgery (SSRF)"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [cloud, code, common-vuln, fixed, metadata, vibe, vulnerable, what]
chunk: 8/10
---

## Prevention Checklist for AI Prompts

```
✅ SSRF PREVENTION:
- Never trust user-supplied URLs — validate, validate, validate
- Use an allowlist of permitted domains/hosts when possible
- Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
- Restrict protocols to HTTP/HTTPS only
- Disable HTTP redirect following
- Set short timeouts (3-5 seconds)
- Resolve DNS and verify IP is not internal
- Use a separate service/firewall for outbound HTTP requests
- Never expose metadata endpoints to application servers
- Use IMDSv2 (AWS) with session-based token
```

---