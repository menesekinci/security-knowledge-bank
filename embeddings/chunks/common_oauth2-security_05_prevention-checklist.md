---
source: "common/oauth2-security.md"
title: "OAuth 2.0 Security — Implicit Grant, Redirect URI, CSRF, PKCE, Token Leakage"
heading: "Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [checklist, common-vuln, cves, major, oauth, prevention, real-world, vibe, what]
chunk: 5/8
---

## Prevention Checklist

```
✅ OAUTH 2.0 SECURITY CHECKLIST:
- Use Authorization Code flow with PKCE — NEVER implicit grant
- Always include and validate a cryptographic 'state' parameter
- Perform exact match on redirect_uri (not prefix/suffix/regex)
- Require HTTPS for ALL redirect URIs
- Validate code_challenge_method = S256 (not 'plain')
- Never log tokens or authorization codes
- Store tokens server-side in HttpOnly, Secure, SameSite cookies
- Implement refresh token rotation (old token invalidated on use)
- Set token expiration (access tokens: 1h max; refresh tokens: rotate)
- Validate scope — don't accept elevated permissions without consent
- Bind authorization codes to client_id and redirect_uri
- Rate-limit token endpoints to prevent brute-force
- Use sender-constrained tokens (DPoP, mTLS) for high-security apps
- Monitor for anomalous token usage patterns
```

---