---
source: "common/webauthn-security.md"
title: "WebAuthn / Passkeys / FIDO2 Security — Credential Management, Attestation, RP Verification"
heading: "intro"
category: "common-vuln"
language: "common"
severity: "high"
tags: [code, common-vuln, cves, explanation, real, secure, vulnerability, vulnerable]
chunk: 1/9
---

# WebAuthn / Passkeys / FIDO2 Security — Credential Management, Attestation, RP Verification

**Severity:** High  
**CWE:** CWE-287 (Improper Authentication), CWE-613 (Insufficient Session Expiration), CWE-522 (Insufficiently Protected Credentials)  
**AI Risk:** High — AI models frequently generate credential managers that bypass WebAuthn API requirements, implement fake "biometric" auth, or misconfigure Relying Party validation  
**OWASP Top 10:2021:** A01 — Broken Access Control, A07 — Identification and Authentication Failures  

---