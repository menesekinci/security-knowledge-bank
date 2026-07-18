---
source: "common/security-testing.md"
title: "🔬 Security Testing Methodology"
heading: "4. Penetration Testing Workflow"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, fuzzing, methodology, penetration, testing, tool, types]
chunk: 5/8
---

## 4. Penetration Testing Workflow

### Standard Pentest Methodology (PTES-aligned)

```
┌──────────────────────────────────────────────────────────┐
│                     PENTEST FLOW                          │
├──────────────────────────────────────────────────────────┤
│  1. Reconnaissance                                        │
│     ├─ Passive: Shodan, Censys, DNS enumeration          │
│     └─ Active: Port scanning, directory enumeration      │
│                                                           │
│  2. Threat Modeling                                       │
│     ├─ Identify attack surface                            │
│     ├─ Map data flows (STRIDE per element)                │
│     └─ Prioritize high-value targets (auth, payment, PII) │
│                                                           │
│  3. Vulnerability Analysis                                │
│     ├─ Automated: SAST + DAST + SCA results               │
│     └─ Manual: Business logic, race conditions, IDOR      │
│                                                           │
│  4. Exploitation                                          │
│     ├─ Chain low-severity issues into high-severity       │
│     ├─ Auth bypass → privilege escalation → data access   │
│     └─ Document proof-of-concept, not full weaponization  │
│                                                           │
│  5. Post-Exploitation                                     │
│     ├─ Assess lateral movement potential                  │
│     ├─ Determine data accessible from compromise point    │
│     └─ Map pivot opportunities                             │
│                                                           │
│  6. Reporting                                             │
│     ├─ Executive summary (business impact)                │
│     ├─ Technical findings (CVE, OWASP Top 10 mapping)     │
│     └─ Remediation roadmap (short-term + long-term)       │
└──────────────────────────────────────────────────────────┘
```

### AI-Generated Code Pentest Checklist

When pentesting code written by AI, add these specific checks:

- [ ] **Prompt injection traces**: Check for eval-like patterns from concatenated instructions
- [ ] **Hallucinated packages**: Verify every third-party import actually exists in the registry
- [ ] **Overly permissive patterns**: AI often writes `permit!`, `allow all`, `disable check`
- [ ] **Missing rate limiting**: AI rarely adds throttling unless explicitly prompted
- [ ] **Hardcoded test credentials**: AI may leave test keys in production code
- [ ] **Incorrect error handling**: Stack traces exposed, overly verbose error messages
- [ ] **Disabled security features**: `verify=False`, `SSL off`, `csrf_exempt`

### Example: Web App Pentest Checklist

```
[ ] SQL Injection (all inputs)
[ ] XSS (reflected, stored, DOM-based)
[ ] CSRF (missing tokens, weak validation)
[ ] Authentication bypass (session prediction, JWT alg=none)
[ ] Authorization flaws (IDOR, privilege escalation)
[ ] SSRF (internal network access)
[ ] SSTI (template engine injection)
[ ] XXE (XML external entities)
[ ] File upload (unrestricted types, path traversal)
[ ] Insecure deserialization
[ ] CORS misconfiguration
[ ] Rate limiting (brute force, enumeration)
[ ] Security headers (CSP, HSTS, X-Frame-Options)
[ ] API security (mass assignment, excessive data exposure)
```

---