---
source: "common/csp-deep.md"
title: "Content Security Policy (CSP) Deep — Bypass Techniques, Nonce vs Hash, Report-uri/report-to, Strict CSP"
heading: "Testing CSP"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 7/8
---

## Testing CSP

**Using curl:**
```bash
# Check CSP header
curl -sI https://example.com | grep -i content-security-policy

# Test in report-only mode first
curl -sI https://example.com | grep -i content-security-policy-report-only
```

**Browser testing:**
```javascript
// Check if CSP blocks eval
try { eval('1+1'); } catch(e) { console.log('CSP blocks eval:', e); }

// Check if CSP reports are working
console.log('CSP report-uri:', document.querySelector('meta[http-equiv="Content-Security-Policy"]'));
```

**Tools:**
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/) — Analyzes CSP policies
- [CSP Validator](https://cspvalidator.org/) — Browser extension for CSP testing
- [Report URI](https://report-uri.com/) — CSP violation monitoring service
- [CSP Scanner](https://github.com/google/csp-evaluator) — Google's CSP analysis library

---