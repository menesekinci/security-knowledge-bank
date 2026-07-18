---
source: "common/engineering/security-principles.md"
title: "Security Engineering Principles"
heading: "7. Principle 6: Open Design"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, defense, fail, least, principle, principles, table]
chunk: 9/14
---

## 7. Principle 6: Open Design

**"The security of a mechanism should not depend on the secrecy of its design or implementation."**

### What It Means

Security through obscurity — hiding source code, using secret algorithms, or relying on undocumented protocols — is not a real control. A system should remain secure even when an attacker knows every detail of its design, except for secrets like passwords and cryptographic keys (Kerckhoffs's principle).

### Common Obscurity Traps

| Obscurity Tactic | Why It Fails |
|---|---|
| Hiding API endpoints (`/secret-admin-panel`) | Discoverable via directory enumeration, web crawlers, or JS source maps |
| Proprietary encryption | Reverse engineering reveals the algorithm; amateur crypto is broken quickly |
| Obfuscated source code | Determined attackers deobfuscate; it only slows down casual inspection |
| Security-through-URL-secrecy | URLs appear in browser history, logs, referrer headers, and bookmarks |
| Custom protocols | Fuzzing and traffic analysis reverse-engineer the protocol faster than you think |

### Why Open Design Works

1. **Public scrutiny finds bugs faster** — open-source libraries like OpenSSL, Curve25519, and OWASP libraries are stronger because they are reviewed by thousands of eyes.
2. **Standard protocols are well-tested** — TLS, OAuth 2.0, and SAML have been attacked for years; their attack surface is well-understood.
3. **Cryptographic security is mathematical, not secret** — AES and SHA-256 are fully public. Their security comes from the hardness of the underlying math, not from hiding the algorithm.
4. **Third-party audits are meaningful** — you cannot get a meaningful security audit of a closed system because the auditor cannot verify what they cannot see.

### Real-World Engineering Scenario

**Scenario:** A startup builds a proprietary authentication protocol because "JWT is too complex." They keep the protocol specification internal.

The protocol has a padding oracle vulnerability discovered during a penetration test. Because the implementation is closed, no community tooling exists to detect the vulnerability, no security researchers can warn other users, and the fix cycle depends entirely on the internal team recognizing the problem.

Had they used standard JWT with well-known libraries, the attack surface would be documented, monitored, and tested by thousands of projects worldwide.

### Nuance

Open design does NOT mean publishing secrets. Cryptographic keys, database passwords, API tokens, and internal network topology are secrets. The *protocols and algorithms* are public. Open design also does not mandate open-source — but open-source projects benefit disproportionately from the principle.

---