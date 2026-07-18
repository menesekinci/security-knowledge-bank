---
source: "common/oidc-saml-security.md"
title: "OIDC / SAML Security — Token Validation, PKCE, Signature Verification"
heading: "intro"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, cves, explanation, prevention, real, vibe-coding, vulnerability, vulnerable]
chunk: 1/7
---

# OIDC / SAML Security — Token Validation, PKCE, Signature Verification

**Severity:** Critical  
**CWE:** CWE-287 (Improper Authentication), CWE-290 (Authentication Bypass by Spoofing), CWE-613 (Insufficient Session Expiration)  
**AI Risk:** High — AI models frequently implement OIDC without PKCE, skip ID token validation, mix up token types, or build SAML with no XML signature verification  
**OWASP Top 10:2021:** A01 — Broken Access Control, A07 — Identification and Authentication Failures  

---