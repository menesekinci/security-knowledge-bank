---
source: "common/security-testing.md"
title: "🔬 Security Testing Methodology"
heading: "5. CI/CD Integration"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, fuzzing, methodology, penetration, testing, tool, types]
chunk: 6/8
---

## 5. CI/CD Integration

```
DEVELOP → COMMIT → BUILD → TEST → DEPLOY
            │         │       │
          SAST       SCA    DAST/IAST
          (pre-     (dep    (runtime
           commit)  scan)   tests)
```

### Minimum Security Gates for AI-Generated Code

| Gate          | Tool                          | Fails Build If           |
|---------------|-------------------------------|--------------------------|
| Secret leak   | truffleHog, Gitleaks          | Any hardcoded credential |
| SAST Critical | Semgrep, CodeQL               | Any critical finding     |
| Dep Vulns     | Trivy, npm audit              | Any CVE ≥ CVSS 7.0      |
| DAST Critical | OWASP ZAP                     | Any high-risk alert      |
| Supply Chain  | SLS provenance, Sigstore      | Unsigned artifact        |

---