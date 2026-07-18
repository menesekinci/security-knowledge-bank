---
source: "common/engineering/security-as-code.md"
title: "🔐 Security as Code"
heading: "6. Security as Code Workflow (Putting It Together)"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [automated, common-vuln, infrastructure, pipeline, policy, remediation, security, what]
chunk: 7/8
---

## 6. Security as Code Workflow (Putting It Together)

```
┌──────────────────────────────┐
│      DEVELOPER COMMIT        │
└─────────┬────────────────────┘
          │
┌─────────▼────────────────────┐
│    PRE-COMMIT HOOKS           │
│  • gitleaks (secrets)        │
│  • trivy fs (vulns)          │
│  • checkov (IaC)             │
└─────────┬────────────────────┘
          │
┌─────────▼────────────────────┐
│     CI PIPELINE               │
│                              │
│  1. Dependency scan          │
│     (Trivy, Snyk, Renovate)  │
│                              │
│  2. IaC scanning             │
│     (Checkov, tfsec, KICS)   │
│                              │
│  3. Policy evaluation        │
│     (Conftest, OPA test)     │
│                              │
│  4. SAST/DAST on app code    │
│     (Semgrep, CodeQL)        │
│                              │
│  5. Build + sign artifact    │
│     (cosign, SBOM gen)       │
│                              │
│  6. Container scan           │
│     (Trivy image)            │
└─────────┬────────────────────┘
          │
┌─────────▼────────────────────┐
│     DEPLOYMENT GATE          │
│  • Admission webhook (K8s)   │
│  • OPA policy check          │
│  • Sign verify               │
│  • Compliance attestation    │
└─────────┬────────────────────┘
          │
┌─────────▼────────────────────┐
│     CONTINUOUS               │
│  • Drift detection           │
│  • Auto-remediation          │
│  • Policy updates via PR     │
└──────────────────────────────┘
```

---