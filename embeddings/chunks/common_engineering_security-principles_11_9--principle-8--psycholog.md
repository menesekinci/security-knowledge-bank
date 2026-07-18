---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "9. Principle 8: Psychological Acceptability"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 11/14
---

## 9. Principle 8: Psychological Acceptability

**"It is essential that the human interface be designed for ease of use, so that users routinely and automatically apply the protection mechanisms correctly."**

### What It Means

If security is harder than insecurity, users will bypass it. A perfectly secure system that nobody uses correctly provides zero security. Security controls that frustrate users create workarounds that are worse than having no control at all.

### The Security-Usability Trade-off Spectrum

```
Perfect Security           Perfect Usability
    │                            │
    │   ┌──────────────────┐    │
    │   │  Overly complex   │    │
    │   │  → Users bypass   │    │
    │   └──────────────────┘    │
    │         ┌──────────┐      │
    │         │  Optimal │      │
    │         │  Balance │      │
    │         └──────────┘      │
    │   ┌──────────────┐        │
    │   │ Too simple   │        │
    │   │ → Not secure │        │
    │   └──────────────┘        │
```

### Real-World Engineering Scenario

**Scenario:** Password policy.

**Bad (violates psychological acceptability):**
- 14+ characters, must include uppercase, lowercase, digit, symbol, no repeating characters, no dictionary words
- Must change every 30 days
- Cannot reuse any of the last 24 passwords
- Two-factor authentication that sends codes via email (easy to miss)

Engineers respond by writing passwords on sticky notes, using password patterns (`April2024!`, `May2024!`), or saving passwords in unprotected spreadsheets.

**Better (respects psychological acceptability):**
- Encourage passphrases (length over complexity)
- Support password managers (long API token, WebAuthn, passkeys)
- Risk-based MFA — only prompt for 2FA on suspicious logins or sensitive operations
- Clear, actionable error messages: "This password appears in known breaches — choose another" vs "Password does not meet policy requirements"

### Practical Guidelines

- **Security should be the default path** — the secure action should also be the easiest action
- **Progressive security** — prompt for additional verification only on high-risk operations (new device, large transfer, privilege change)
- **Clear feedback** — tell the user *why* something was blocked and *what they can do about it*
- **Recoverability** — locked-out users should have a clear, non-humiliating recovery path
- **Developer empathy** — engineers are users too. SDKs and APIs should have secure defaults and obvious "right ways" to do things

---