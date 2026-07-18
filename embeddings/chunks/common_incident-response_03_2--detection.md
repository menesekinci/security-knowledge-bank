---
source: "common/incident-response.md"
title: "🚨 Incident Response for Developers"
heading: "2. Detection"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, containment, detection, eradication, phases, recovery]
chunk: 3/18
---

## 2. Detection

### How Incidents Are Detected

| Source                     | Example Trigger                                      | Response Time |
|----------------------------|------------------------------------------------------|---------------|
| **Security scanner**       | SAST/DAST finding in CI                              | Minutes       |
| **SIEM alert**             | Anomalous network traffic, repeated 401s             | Minutes       |
| **Intrusion detection**    | IDS/IPS signature match                              | < 1 hour      |
| **User report**            | Customer reports data breach                         | < 1 hour      |
| **Bug bounty**             | Validated vulnerability report                       | < 24 hours    |
| **Threat intel feed**      | CVE announced with active exploitation               | < 24 hours    |
| **Cloud provider notice**  | AWS GuardDuty finding, GCP Security Command Center   | < 1 hour      |
| **Dependency alert**       | Dependabot/GitHub Advisory with malicious package    | < 1 hour      |
| **Production monitoring**  | Error budget burn, increased 5xx rate                | < 5 minutes   |
| **AI behavior anomaly**    | AI-generated code behaves unexpectedly in prod       | ASAP          |

### Detection Checklist

- [ ] Are we monitoring auth failures (401s, repeated login attempts)?
- [ ] Are we tracking dependency CVE disclosures?
- [ ] Do we have a way to detect secret leaks (GitGuardian, Gitleaks CI)?
- [ ] Are we alerting on anomalous API usage patterns?
- [ ] Do we monitor cloud API calls for credential abuse?
- [ ] Are we checking SBOMs against known vulnerability databases?
- [ ] Is there a channel for users to report security issues?

### Severity Classification

| Severity | CVSS Range | Examples                                  | Response Time   |
|----------|------------|-------------------------------------------|-----------------|
| 🚨 Critical | 9.0–10.0 | RCE, auth bypass, data breach            | < 1 hour        |
| 🔴 High    | 7.0–8.9   | SQL injection, SSRF, significant data leak | < 4 hours       |
| 🟡 Medium  | 4.0–6.9   | XSS, CSRF, IDOR limited scope            | < 24 hours      |
| 🟢 Low     | 0.1–3.9   | Information disclosure, minor misconfig   | < 1 week        |

---