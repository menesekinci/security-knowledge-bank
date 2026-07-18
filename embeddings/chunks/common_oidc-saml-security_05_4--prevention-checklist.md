---
source: "common/oidc-saml-security.md"
title: "OIDC / SAML Security — Token Validation, PKCE, Signature Verification"
heading: "4. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, cves, explanation, prevention, real, vibe-coding, vulnerability, vulnerable]
chunk: 5/7
---

## 4. Prevention Checklist

### OIDC
- [ ] **Always use Authorization Code + PKCE** (S256 challenge method) — never Implicit Flow
- [ ] **Validate ID Token signature** against provider's JWKS endpoint
- [ ] **Verify `iss` (issuer)** matches the expected OIDC provider URL exactly
- [ ] **Verify `aud` (audience)** includes your client ID
- [ ] **Verify `exp` (expiration)** and `iat` (issued at) timestamps
- [ ] **Use and verify `nonce`** to prevent replay attacks
- [ ] **Use and verify `state`** parameter to prevent CSRF attacks
- [ ] **Never send ID token to APIs** — use access token for API authorization
- [ ] **Never store tokens in `localStorage`** — use BFF (Backend for Frontend) pattern with HttpOnly cookies
- [ ] **Implement refresh token rotation** — invalidate old refresh tokens when new ones are issued
- [ ] **Reject `alg: "none"`** tokens — enforce RS256, ES256, or EdDSA only
- [ ] **Implement client authentication** (client_secret_basic, private_key_jwt) for token endpoint
- [ ] **Limit token lifetime** — access tokens ≤15 minutes, refresh tokens rotated

### SAML
- [ ] **Always verify XML Digital Signature** — never trust unsigned SAML assertions
- [ ] **Use a robust XML parser** with XXE protection enabled (lxml, not xml.etree.ElementTree)
- [ ] **Defend against XML Signature Wrapping** — verify only one Assertion element, validate Reference URI
- [ ] **Verify Issuer** (entity ID) matches the trusted IdP exactly
- [ ] **Verify Audience Restriction** — must include your SP entity ID
- [ ] **Verify time constraints** (NotBefore, NotOnOrAfter) with clock skew tolerance
- [ ] **Verify Response Status** is `Success`
- [ ] **Use `authnRequest` binding** with signed requests when possible
- [ ] **Enforce HTTPS** for all SAML endpoints (SSO URL, ACS URL)
- [ ] **Certificate rotation** — monitor and rotate IdP signing certificates before expiry
- [ ] **Log all SAML authentication attempts** including failures
- [ ] **Avoid `redirect` binding for sensitive assertions** — prefer `POST` binding

---