---
source: "common/cors-deep.md"
title: "CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs"
heading: "Testing CORS"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [coding, common-vuln, cors, headers, vibe, vulnerability, what]
chunk: 9/10
---

## Testing CORS

**Using curl:**
```bash
# Test wildcard
curl -H "Origin: https://evil.com" -I https://target.com/api

# Check response headers
curl -H "Origin: null" -I https://target.com/api

# Test with credentials
curl -H "Origin: https://evil.com" -H "Cookie: session=abc" -I https://target.com/api
```

**Using browser console:**
```javascript
// Test if CORS allows your origin
fetch('https://target.com/api/data', {
    credentials: 'include',
    headers: { 'X-Custom': 'test' }
}).then(r => r.text()).then(console.log).catch(console.log);
```

**Tools:**
- [CORS Test](https://webbrowsertools.com/cors-test/) — Online CORS checker
- Burp Suite — Active/passive CORS scanning
- corsy — CORS misconfiguration scanner (Python)
- [cors-test](https://www.npmjs.com/package/cors-test) — Node.js CORS testing tool

---