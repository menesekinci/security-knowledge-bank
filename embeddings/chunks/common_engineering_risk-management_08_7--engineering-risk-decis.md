---
source: "common/engineering/risk-management.md"
title: "Security Risk Management for Engineers"
heading: "7. Engineering Risk Decisions"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [assessment, building, common-vuln, likelihood, risk, threat, treatment]
chunk: 8/9
---

## 7. Engineering Risk Decisions

Beyond formal risk management, engineers make risk decisions every day. Here are the most common scenarios with a security lens.

### 7.1 Technical Debt as Security Risk

Not all technical debt is a security problem, but some types directly increase risk:

| Debt Type | Security Impact | When to Escalate |
|---|---|---|
| **Outdated dependencies** | Known CVEs in libraries | When a library has a CVE with active exploitation |
| **Untested code paths** | Logic bugs that lead to auth bypass | When the debt is in auth, crypto, or input validation |
| **Hardcoded credentials** | Direct credential exposure | Always — fix immediately |
| **No input validation** | Injection attacks | When the code parses external input |
| **Monolith without isolation** | Blast radius is the entire app | When the app handles sensitive data |

**Decision framework:** When incurring tech debt, ask: "If an attacker found this weakness, what could they do?" If the answer involves data exfiltration, privilege escalation, or service compromise, the debt is a security risk that needs a formal entry in the risk register.

### 7.2 Third-Party Dependency Risk

Every dependency is a delegation of trust. You take on the dependency's security posture — its development practices, incident response, and vulnerability disclosure.

**Dependency risk assessment:**
1. **Criticality:** How much does the app depend on this library? Is it in the auth, crypto, or data path?
2. **Maintainer health:** Is the project actively maintained? How many maintainers? Are they responsive to security issues?
3. **Attack surface:** Does the library handle network input? Parse untrusted data? Execute system commands?
4. **Supply chain:** Has the library been compromised before? Does it have unnecessary transitive dependencies?

**Mitigation actions:**
- Pin versions with lockfiles.
- Use Software Bill of Materials (SBOM) tools (Syft, Trivy).
- Subscribe to security advisories for critical dependencies (GitHub Advisory DB, OSV).
- For high-risk dependencies: mirror the package, review diffs before updating, consider alternatives.

### 7.3 Open Source vs. Commercial Trade-offs

| Dimension | Open Source | Commercial |
|---|---|---|
| **Visibility** | Full source code — you can audit it | Closed source — you rely on vendor claims |
| **Response time** | Variable (community-driven) | Contractual SLAs |
| **Cost** | Free (but support costs time) | License fees (but vendor handles vulnerabilities) |
| **Control** | You can patch it yourself | You wait for the vendor |
| **Longevity** | Project can be abandoned | Vendor can go out of business |

**Security recommendation:** For critical security functions (crypto, auth, certificate validation), use well-audited open source (it has more eyes) with commercial support if needed. For niche or compliance-sensitive functions where auditability matters less than guaranteed SLAs, commercial vendors are often lower risk.

---