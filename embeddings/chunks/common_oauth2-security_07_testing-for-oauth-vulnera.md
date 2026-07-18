---
source: "common/oauth2-security.md"
title: "OAuth 2.0 Security — Implicit Grant, Redirect URI, CSRF, PKCE, Token Leakage"
heading: "Testing for OAuth Vulnerabilities"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [checklist, common-vuln, cves, major, oauth, prevention, real-world, vibe, what]
chunk: 7/8
---

## Testing for OAuth Vulnerabilities

**Authorization request tampering:**
```
Manipulate:
- redirect_uri to different origin/path
- response_type from 'code' to 'token' (downgrade to implicit)
- scope to elevated permissions
- state to known value or remove it
```

**Code injection check:**
```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=ATTACKER_CODE&client_id=123&redirect_uri=https://client.com/callback
```

**Tools:**
- Burp Suite — OAuth scanning, interception, replay
- oauth2_proxy security scanner
- OWASP ZAP — OAuth add-on
- Custom curl scripts for redirect URI fuzzing

---