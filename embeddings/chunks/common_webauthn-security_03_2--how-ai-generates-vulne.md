---
source: "common/webauthn-security.md"
title: "WebAuthn / Passkeys / FIDO2 Security — Credential Management, Attestation, RP Verification"
heading: "2. How AI Generates Vulnerable Code"
category: "common-vuln"
language: "common"
severity: "high"
tags: [code, common-vuln, cves, explanation, real, secure, vulnerability, vulnerable]
chunk: 3/9
---

## 2. How AI Generates Vulnerable Code

### 2.1 "Add passkey login to my app" → DIY Crypto Instead of WebAuthn

```
AI generates:
- A custom key-pair generator using SubtleCrypto
- Private keys stored in localStorage
- Custom challenge-response protocol over fetch()
- No origin binding
- No attestation
```

This is **not** WebAuthn. It's custom cryptography with zero security guarantees.

### 2.2 "Add FaceID login" → Stored Password Check Instead of Biometric

```
AI generates:
- A "biometric" button that just checks a stored session flag
- A password field disguised as a FaceID scan
- No integration with navigator.credentials or platform APIs
```

---