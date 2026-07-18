---
source: "common/csp-deep.md"
title: "Content Security Policy (CSP) Deep — Bypass Techniques, Nonce vs Hash, Report-uri/report-to, Strict CSP"
heading: "Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 5/8
---

## Prevention Checklist

```
✅ CSP IMPLEMENTATION CHECKLIST:
- Use strict CSP (nonce + strict-dynamic) instead of URL whitelisting
- NEVER use 'unsafe-inline' on production — use nonces or hashes
- NEVER use 'unsafe-eval' — eliminates eval(), setTimeout(string), Function()
- Set object-src 'none' — blocks Flash, Java, and plugin-based bypasses
- Set base-uri 'none' or restrict to specific origins
- Set frame-ancestors to prevent clickjacking (instead of X-Frame-Options)
- Keep script-src URLs minimal — avoid CDN whitelists with JSONP
- Serve user uploads from separate domain with script-src: 'none'
- Use Reporting-Endpoints + report-to for CSP violation monitoring
- Test CSP in 'Report-Only' mode first before enforcing
- Use CSP Evaluator (https://csp-evaluator.withgoogle.com/)
- Regularly review CSP violation reports for attack attempts
- Implement rate-limiting on CSP report endpoints
- Never include 'unsafe-inline' as fallback without testing
- Upgrade from report-uri to report-to for modern browsers
```

---