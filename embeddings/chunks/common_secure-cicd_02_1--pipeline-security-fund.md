---
source: "common/secure-cicd.md"
title: "🚀 CI/CD Security (Secure CI/CD Pipeline)"
heading: "1. Pipeline Security Fundamentals"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [artifact, common-vuln, dependency, generation, pipeline, sbom, scanning, secret, security, signing]
chunk: 2/9
---

## 1. Pipeline Security Fundamentals

### The CI/CD Attack Surface

```
                    ┌──────────────────┐
                    │   SOURCE CODE    │
                    │   (Git/SCM)      │ ← Commit injection, secret leak
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │   CI PIPELINE    │ ← Pipeline injection, poisoned builds
                    │ (GitHub Actions/ │
                    │  Jenkins/GitLab) │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  ARTIFACT REPO   │ ← Dependency confusion, typosquatting
                    │ (npm/PyPI/Docker)│
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │   DEPLOYMENT     │ ← Misconfig, credential theft
                    └──────────────────┘
```

### Key Threats in CI/CD

| Threat Vector         | Example                                         | Impact                     |
|-----------------------|-------------------------------------------------|----------------------------|
| SCM compromise        | Attacker pushes to protected branch             | Malicious code in prod     |
| CI pipeline injection | Malicious PR with workflow override             | Runners exfiltrate secrets |
| Secret leakage        | npm publish includes `.env`                     | Cloud credential theft     |
| Dependency confusion  | Private package name taken on public registry   | RCE via typo-squatted dep  |
| Artifact tampering    | Unsigned binary modified in transit             | Supply chain compromise    |
| Runner poisoning      | Compromised CI runner exfiltrates build secrets  | All secrets exposed        |
| Time-of-check/time-of-use | Approval then swap                          | Untested code in prod      |

### Minimum Security Controls

```
┌──────────────────────────────────────────────────────────┐
│                  CI/CD SECURITY CONTROLS                   │
├──────────────────────────────────────────────────────────┤
│ 1. [ ] BRANCH PROTECTION                                   │
│     ├─ Require PRs for main branches                       │
│     ├─ Require status checks before merge                  │
│     └─ Require signed commits (GPG/SSH)                    │
│                                                            │
│ 2. [ ] SECRET MANAGEMENT                                    │
│     ├─ Never hardcode secrets in repo                      │
│     ├─ Use CI secret store (GitHub Secrets, Vault)         │
│     └─ Rotate secrets automatically on leak                │
│                                                            │
│ 3. [ ] PIPELINE INTEGRITY                                   │
│     ├─ Pin CI runner versions (ubuntu-22.04 not latest)    │
│     ├─ Use OIDC for cloud auth (no static creds)            │
│     └─ Validate CI config changes require review           │
│                                                            │
│ 4. [ ] ARTIFACT INTEGRITY                                   │
│     ├─ Sign all build artifacts (Sigstore/Cosign)          │
│     ├─ Generate SBOM for every build                       │
│     └─ Verify signatures before deployment                 │
│                                                            │
│ 5. [ ] SUPPLY CHAIN SECURITY                                │
│     ├─ Lock dependency files (lockfile, pin versions)      │
│     ├─ Verify package integrity (hash check, sig verify)   │
│     └─ Denylist unverified or deprecated packages          │
└──────────────────────────────────────────────────────────┘
```

---