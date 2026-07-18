---
source: "common/http-headers-security.md"
title: "HTTP Security Headers — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy"
heading: "Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [additional, common-vuln, essential, header, important, priority, vibe, what]
chunk: 7/10
---

## Prevention Checklist

```
✅ HTTP SECURITY HEADERS CHECKLIST:
- Set Strict-Transport-Security with max-age ≥ 1 year, includeSubDomains, preload
- Submit to https://hstspreload.org/ for permanent HTTPS enforcement
- Set X-Frame-Options: DENY (or SAMEORIGIN if framing on same origin needed)
- Set X-Content-Type-Options: nosniff on ALL responses
- Set Referrer-Policy: strict-origin-when-cross-origin
- Set Permissions-Policy to restrict features to only what you need
- Set Content-Security-Policy with strict directives (see csp-deep.md)
- Remove X-XSS-Protection header (deprecated, use CSP instead)
- Set Cache-Control: no-store on sensitive pages
- Add Clear-Site-Data on logout endpoints
- Use Cross-Origin-Resource-Policy for additional isolation
- Test headers: https://securityheaders.com/
- Audit headers with every deploy (CI/CD pipeline check)
- Header consistency: apply at reverse proxy/load balancer, not just app layer
- Document header decisions in a security policy file
```

---