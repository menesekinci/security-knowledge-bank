---
source: "common/http-headers-security.md"
title: "HTTP Security Headers — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy"
heading: "Testing Security Headers"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [additional, common-vuln, essential, header, important, priority, vibe, what]
chunk: 9/10
---

## Testing Security Headers

**Using curl:**
```bash
# Check all security headers
curl -sI https://example.com | head -20

# HSTS check
curl -sI https://example.com | grep -i strict-transport

# X-Frame-Options check
curl -sI https://example.com | grep -i x-frame-options

# Full header audit
curl -s -D- https://example.com | grep -E "(Strict-Transport|X-Frame|X-Content|Referrer|Permissions|Content-Security)"
```

**Online tools:**
- [SecurityHeaders.com](https://securityheaders.com/) — Analyzes and grades your security headers (A+ target)
- [Mozilla Observatory](https://observatory.mozilla.org/) — Comprehensive security scan
- [HSTS Preload Check](https://hstspreload.org/) — Check HSTS preload status

**CI/CD integration:**
```bash
# Using npm package: lighthouse-security-headers
npx security-headers https://example.com --fail-if-below=50
```

---