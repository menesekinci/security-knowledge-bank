---
source: "common/webauthn-security.md"
title: "WebAuthn / Passkeys / FIDO2 Security — Credential Management, Attestation, RP Verification"
heading: "6. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "high"
tags: [code, common-vuln, cves, explanation, real, secure, vulnerability, vulnerable]
chunk: 7/9
---

## 6. Prevention Checklist

- [ ] **Always use `navigator.credentials.create()` / `.get()`** — never hand-roll crypto for passkeys
- [ ] **Set `rp.id` explicitly** to your domain (no wildcards, no subdomain mismatch)
- [ ] **Validate origin server-side** — compare against `expectedOrigin` parameter in every registration and authentication
- [ ] **Store challenge server-side** — never trust the client to provide or store challenges
- [ ] **Require `userVerification: "required"`** — force biometric/PIN for high-security applications
- [ ] **Verify attestation** — for enterprise deployments, verify certificate chain against trusted roots
- [ ] **Check sign count** — monotonic counter to detect cloned authenticators
- [ ] **Use Conditional Mediation** (`mediation: "conditional"`) for seamless UX without modal popups
- [ ] **Never store private keys in localStorage/IndexedDB** — use platform authenticator only
- [ ] **Never implement fake "biometric" auth** — always use platform biometric APIs via WebAuthn
- [ ] **Use the `requireResidentKey` option** for discoverable credentials (passkeys)
- [ ] **Clean up credentials on user deletion** — see CVE-2021-32726
- [ ] **Enforce server-side WebAuthn policies** — don't rely on client-side enforcement (see CVE-2026-8830)

---