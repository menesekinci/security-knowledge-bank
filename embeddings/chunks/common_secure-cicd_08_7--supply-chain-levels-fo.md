---
source: "common/secure-cicd.md"
title: "🚀 CI/CD Security (Secure CI/CD Pipeline)"
heading: "7. Supply Chain Levels for Software Artifacts (SLSA)"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [artifact, common-vuln, dependency, generation, pipeline, sbom, scanning, secret, security, signing]
chunk: 8/9
---

## 7. Supply Chain Levels for Software Artifacts (SLSA)

| SLSA Level | Requirements                          | Status   |
|------------|---------------------------------------|----------|
| L1         | Build process documented              | Baseline |
| L2         | Build runs on hosted CI               | Common   |
| L3         | Hardened CI + no user-controlled steps| Target   |
| L4         | Two-person review + hermetic builds   | Ideal    |

### Achieving SLSA L3

```yaml
# Requirements for SLSA L3:
# 1. Build as code (no manual steps)  ✅
# 2. Ephemeral environment            ✅ (GitHub Actions)
# 3. Isolated (no external influence)  ✅ (custom runner)
# 4. No user-controlled build steps   ⚠️ (pin actions to SHA)
# 5. Provenance attestation           ✅ (cosign attest)
# 6. Non-falsifiable provenance       ⚠️ (OIDC-based)
```

---