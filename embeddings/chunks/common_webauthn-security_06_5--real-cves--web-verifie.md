---
source: "common/webauthn-security.md"
title: "WebAuthn / Passkeys / FIDO2 Security — Credential Management, Attestation, RP Verification"
heading: "5. Real CVEs (Web-Verified)"
category: "common-vuln"
language: "common"
severity: "high"
tags: [code, common-vuln, cves, explanation, real, secure, vulnerability, vulnerable]
chunk: 6/9
---

## 5. Real CVEs (Web-Verified)

| CVE ID | CVSS | Affected | Vulnerability | CWE |
|--------|------|----------|--------------|-----|
| CVE-2020-8236 | 6.8 MEDIUM | Nextcloud Server ≤19.0.1 | WebAuthn PIN requested but not verified during passwordless login — user felt 2FA was active when it wasn't | CWE-287 |
| CVE-2021-32726 | 7.1 HIGH | Nextcloud <19.0.13, <20.0.11, <21.0.3 | WebAuthn tokens not deleted after user deletion — reused username allows previous user account takeover (Nextcloud CNA score; NVD adopted a 9.8 primary) | CWE-708 |
| CVE-2021-32800 | 8.1 HIGH | Nextcloud <20.0.12, <21.0.4, <22.1.0 | WebAuthn 2FA bypass — attacker with password or WebAuthn device key can bypass MFA entirely | CWE-306 |
| CVE-2021-40818 | 9.8 CRITICAL | Glewlwyd SSO ≤2.5.3 | Buffer overflow in FIDO2 signature validation during WebAuthn registration | CWE-120 |
| CVE-2021-38299 | 9.8 CRITICAL | Webauthn Framework <3.2.9, <3.3.4 | Missing user presence check — attacker with physical FIDO2 device access can login without user interaction | CWE-287 |
| CVE-2022-27240 | 9.8 CRITICAL | Glewlwyd SSO 2.x <2.6.2 | Buffer overflow associated with webauthn assertion processing | CWE-120 |
| CVE-2023-49208 | 9.8 CRITICAL | Glewlwyd SSO <2.7.6 | Buffer overflow during FIDO2 credentials validation in webauthn registration | CWE-120 |
| CVE-2025-53102 | 9.8 CRITICAL | Discourse <3.4.7 stable | WebAuthn challenge reuse — the server-generated 2FA challenge is not invalidated/bound to a single ceremony, so a captured challenge-response can be replayed | CWE-384 |
| CVE-2026-28787 | 8.2 HIGH | OneUptime ≤10.0.11 | WebAuthn challenge not stored server-side — no origin binding, replayable credentials | CWE-287 |
| CVE-2026-31835 | 5.4 MEDIUM | Vaultwarden ≤1.35.4 | `validate_webauthn_login()` updates persistent credential metadata (`backup_eligible`/`backup_state`) from unverified `authenticatorData` before signature validation → persistent WebAuthn 2FA DoS (NVD v3.1 5.4; GHSA CVSS 4.0 = 5.3) | CWE-345 |
| CVE-2026-8830 | 4.3 MEDIUM | Keycloak | Authenticated user bypasses WebAuthn policy during credential registration via client-side JS manipulation — server-side policy not enforced | CWE-287 |

---