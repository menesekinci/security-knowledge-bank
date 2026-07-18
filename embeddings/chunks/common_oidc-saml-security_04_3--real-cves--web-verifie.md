---
source: "common/oidc-saml-security.md"
title: "OIDC / SAML Security — Token Validation, PKCE, Signature Verification"
heading: "3. Real CVEs (Web-Verified)"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, cves, explanation, prevention, real, vibe-coding, vulnerability, vulnerable]
chunk: 4/7
---

## 3. Real CVEs (Web-Verified)

### OIDC / OAuth CVEs

| CVE ID | CVSS | Affected | Vulnerability | CWE |
|--------|------|----------|--------------|-----|
| CVE-2021-44878 | 7.5 HIGH | pac4j ≤5.3.0 | "none" algorithm accepted for OIDC tokens — unsigned ID tokens trusted by default | CWE-347 |
| CVE-2021-22573 | 7.3 HIGH | Google OAuth IDToken verifier library | ID token signature verification skipped — accepts arbitrarily forged tokens (NVD primary 7.3; secondary 8.7) | CWE-347 |
| CVE-2022-31105 | 8.3 HIGH | Argo CD 0.4.0–2.2.10, 2.3.0–2.3.5, 2.4.0–2.4.4 | Improper certificate validation in OIDC — attacker can spoof any OIDC provider | CWE-295 |
| CVE-2023-27490 | 8.1 HIGH | NextAuth.js <4.20.1 | PKCE bypass in OAuth — authorization code interception without verifier validation | CWE-287 |
| CVE-2024-49755 | 3.1 LOW | Duende IdentityServer | Insufficient cnf claim validation in DPoP access tokens | CWE-287 |
| CVE-2025-4144 | 9.8 CRITICAL | Cloudflare workers-oauth-provider | PKCE implementation flaw — authorization code injection | CWE-287 |
| CVE-2026-28498 | 7.5 HIGH | Authlib <1.6.9 | OIDC token validation vulnerability — insufficient algorithm validation | CWE-347 |
| CVE-2026-11800 | 8.1 HIGH | Keycloak | JWT algorithm confusion in OIDC Authorization Grant flow — signature bypass | CWE-347 |

### SAML CVEs

| CVE ID | CVSS | Affected | Vulnerability | CWE |
|--------|------|----------|--------------|-----|
| CVE-2018-5241 | 9.8 CRITICAL | Symantec ASG 6.6/6.7, ProxySG 6.5/6.6/6.7 | SAML authentication bypass — attacker can forge authentication | CWE-287 |
| CVE-2018-5387 | 7.5 HIGH | Wizkunde SAMLBase | XML DOM traversal and canonicalization misuse — attacker manipulates SAML data without invalidating signature | CWE-347 |
| CVE-2019-3878 | 8.1 HIGH | mod_auth_mellon <0.14.2 | SAML auth bypass when Apache configured as reverse proxy — crafted URL can bypass authentication check | CWE-287 |
| CVE-2019-1006 | 7.5 HIGH | WCF/WIF (.NET) | SAML token signing bypass — arbitrary symmetric keys accepted for signature verification | CWE-347 |
| CVE-2017-11427 | 9.8 CRITICAL | OneLogin PythonSAML ≤2.3.0 | XML DOM traversal/canonicalization — signature bypass via XML manipulation (NVD primary 9.8; secondary 7.7) | CWE-347 |
| CVE-2020-5390 | 7.5 HIGH | PySAML2 <5.0.0 | XML Signature Wrapping (XSW) — enveloped signature not enforced | CWE-347 |
| CVE-2015-5253 | 4.0 MEDIUM | Apache CXF <2.7.18, 3.0.x <3.0.7, 3.1.x <3.1.3 | SAML bypass via crafted response with valid signature from arbitrary user | CWE-287 |
| CVE-2020-2021 | 10.0 CRITICAL | PAN-OS (Palo Alto Networks) | SAML certificate validation bypass when "Validate Identity Provider Certificate" disabled | CWE-295 |
| CVE-2020-27846 | 9.8 CRITICAL | crewjam/saml Go library | Signature verification vulnerability — SAML authentication bypass | CWE-347 |
| CVE-2020-4427 | 9.8 CRITICAL | IBM Data Risk Manager 2.0.1–2.0.6 | SAML authentication bypass via crafted request | CWE-287 |
| CVE-2024-9487 | 9.1 CRITICAL | GitHub Enterprise Server | SAML SSO signature verification bypass — authentication bypass | CWE-347 |
| CVE-2025-59718 | 9.8 CRITICAL | Fortinet FortiOS 7.0.0–7.6.3 | SAML signature verification bypass | CWE-347 |
| CVE-2025-54982 | 9.6 CRITICAL | Zscaler Admin UI | SAML cryptographic signature verification bypass — privilege escalation | CWE-347 |
| CVE-2026-54774 | 7.4 HIGH | CoreWCF <1.8.1, <1.9.1 | SamlSerializer skips final SignatureValue verification | CWE-347 |

---