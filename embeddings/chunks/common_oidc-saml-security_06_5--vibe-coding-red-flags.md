---
source: "common/oidc-saml-security.md"
title: "OIDC / SAML Security — Token Validation, PKCE, Signature Verification"
heading: "5. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, cves, explanation, prevention, real, vibe-coding, vulnerability, vulnerable]
chunk: 6/7
---

## 5. Vibe-Coding Red Flags

| Red Flag | What AI Might Generate | Secure Alternative |
|----------|----------------------|-------------------|
| "Add Google login with React" | Implicit flow, access token in URL, no PKCE | Authorization Code + PKCE via BFF pattern |
| "Verify the JWT token" | Just decodes base64, no signature check | Verify signature against JWKS, validate all claims |
| "Send the ID token to my API" | Uses ID token as bearer token for API | Access token for API, ID token for authentication only |
| "Store the token for auto-login" | Saves tokens to localStorage | BFF pattern with HttpOnly session cookie |
| "Add SAML SSO" | Unauthenticated ACS endpoint, no signature verification | Full XML signature verification with XSW defense |
| "Parse the SAML response" | `xml.etree.ElementTree` without XXE protection | lxml with secure defaults, signature verification via signxml |
| "Allow 'none' algorithm for flexibility" | Accepts unsigned tokens | Reject 'none', enforce RS256/ES256/EdDSA |
| "Use the access token to get user info" | Access token sent to UserInfo endpoint (redundant) | ID token already contains user claims; UserInfo optional for additional claims |
| "Skip PKCE for server-side apps" | Hidden assumption: "it's safe because it's confidential" | Always use PKCE — mitigates authorization code interception |
| "Code verifier = 'abc123'" | Static/predictable code verifier | Secure random (32+ bytes), SHA-256 hashed for challenge |
| "Handle SAML metadata automatically" | Auto-imports any IdP metadata without verification | Pin metadata, verify certificates, check entity IDs |

---