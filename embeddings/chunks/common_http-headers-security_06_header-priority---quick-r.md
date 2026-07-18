---
source: "common/http-headers-security.md"
title: "HTTP Security Headers — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy"
heading: "Header Priority & Quick Reference"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [additional, common-vuln, essential, header, important, priority, vibe, what]
chunk: 6/10
---

## Header Priority & Quick Reference

```http
# 🔴 Critical — Missing these headers exposes users to serious attacks:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff

# 🟠 Important — Missing these reduces privacy and control:
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=(), interest-cohort=()

# 🔵 Defense-in-Depth — Add these for additional security:
Content-Security-Policy: (see csp-deep.md)
Cross-Origin-Resource-Policy: same-site
Cross-Origin-Opener-Policy: same-origin
Clear-Site-Data: "cookies", "storage"  # On logout
```

---