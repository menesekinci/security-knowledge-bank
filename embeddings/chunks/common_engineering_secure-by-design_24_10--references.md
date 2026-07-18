---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "10. References"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 24/25
---

## 10. References

### OWASP Application Security Verification Standard (ASVS)

OWASP ASVS provides a tiered set of security requirements for web applications:

| Level | Description | When to Target |
|---|---|---|
| L1 | Automated verification — basic vulnerabilities | All applications |
| L2 | Manual verification — standard defenses | Applications handling sensitive data |
| L3 | Advanced verification — defense in depth | Critical applications (fintech, healthcare, infrastructure) |

**Key ASVS sections for design:**
- V2: Authentication Verification Requirements
- V3: Session Management Verification Requirements
- V4: Access Control Verification Requirements
- V5: Validation, Sanitization and Encoding
- V8: Data Protection
- V14: Configuration

### NIST SP 800-160 Vol. 1 (Systems Security Engineering)

NIST's framework for integrating security into systems engineering:
- Part 2: Security design principles
- Part 3: Risk management in design
- Appendix F: Security design pattern catalog

### CISA Secure by Design

CISA's 2023 "Secure by Design" pledge — principles for software manufacturers:
1. **Take ownership of security outcomes** — ship secure, not just "fast"
2. **Embrace radical transparency** — publish vulnerability data, don't hide it
3. **Lead from the top** — executives own security, not just the CISO

### Additional References

- **MITRE CWE-TOP 25** — design-level weakness patterns to avoid
- **NIST SP 800-53 Rev 5** — comprehensive control catalog for federal systems
- **ISO 27001:2022 Annex A** — control set for information security management
- **Cloud Security Alliance (CSA) Cloud Controls Matrix** — cloud-specific design controls

---