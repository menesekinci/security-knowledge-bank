---
source: "common/webauthn-security.md"
title: "WebAuthn / Passkeys / FIDO2 Security — Credential Management, Attestation, RP Verification"
heading: "7. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "high"
tags: [code, common-vuln, cves, explanation, real, secure, vulnerability, vulnerable]
chunk: 8/9
---

## 7. Vibe-Coding Red Flags

| Red Flag | What AI Might Generate | Secure Alternative |
|----------|----------------------|-------------------|
| "Add passkey login to my React app" | Custom `crypto.subtle` key generation + localStorage storage | `navigator.credentials.create()` with platform authenticator |
| "Add FaceID/TouchID login" | A password field + "biometric" CSS styling | WebAuthn with `userVerification: 'required'` + platform authenticator |
| "Store WebAuthn credentials for offline" | Serialize private keys as JSON, store in IndexedDB | Let platform authenticator manage keys; store only credential ID server-side |
| "Generate a challenge" | `Math.random().toString()` or `new Date().getTime()` | `crypto.getRandomValues()` (32 bytes minimum) with server-side storage |
| "Skip attestation for simplicity" | Accept all `attestation: 'none'` responses without checking | Use `attestation: 'direct'` for sensitive deployments |
| "Make WebAuthn work on iframe" | Using WebAuthn inside cross-origin iframe (browser blocks it) | Top-level navigation only; use postMessage to parent window |
| "Backup my passkeys to the cloud" | Upload private key material to a REST API | Platform-managed sync (iCloud Keychain, Google Password Manager, etc.) |
| "Auto-login with passkeys" | Auto-invoke `navigator.credentials.get()` without user gesture | Conditional Mediation (`mediation: 'conditional'`) or user-initiated button |

---