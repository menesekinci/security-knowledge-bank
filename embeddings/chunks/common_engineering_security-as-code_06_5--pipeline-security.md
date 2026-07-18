---
source: "common/engineering/security-as-code.md"
title: "🔐 Security as Code"
heading: "5. Pipeline Security"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [automated, common-vuln, infrastructure, pipeline, policy, remediation, security, what]
chunk: 6/8
---

## 5. Pipeline Security

The CI/CD pipeline is the most privileged system in the organization — it has access to source code, secrets, cloud credentials, and production environments. Securing it is Security as Code's final critical layer.

### CI/CD Pipeline as Attack Surface

```
┌──────────────────────────────────────────────────────────────────┐
│                    PIPELINE ATTACK VECTORS                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│ 1. POISONED PIPELINE EXECUTION                                   │
│    └─ Attacker controls pipeline definition via malicious PR      │
│                                                                   │
│ 2. INJECTED BUILD TOOLS                                          │
│    └─ Compromised build image or CI runner                        │
│                                                                   │
│ 3. DEPENDENCY CONFUSION                                          │
│    └─ Malicious package with same name as internal dep            │
│                                                                   │
│ 4. CREDENTIAL THEFT                                              │
│    └─ Exposed CI secrets (env vars, tokens)                       │
│                                                                   │
│ 5. ARTIFACT TAMPERING                                            │
│    └─ Modified build output before deployment                     │
│                                                                   │
│ 6. RECURSIVE BUILD / CI CD FROM FORK                             │
│    └─ PR from fork triggers build with org secrets                │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Signed Artifacts and SLSA Levels

[SLSA (Supply chain Levels for Software Artifacts)](https://slsa.dev/) provides a security framework for artifact integrity.

| SLSA Level | Requirements | Practical Implementation |
|-----------|--------------|--------------------------|
| **Level 1** | Build process documented, provenance generated | Provenance attestation (e.g., GitHub attestations) |
| **Level 2** | Signed provenance, hosted build, no CI from forks | Sigstore cosign signing, GitHub Actions hosted runners |
| **Level 3** | Hermetic build, reproducible, isolated | Distroless containers, hardened CI, no network in build |
| **Level 4** | Two-person review, air-gapped build, all dependencies verified | Dedicated build service, signed SLSA provenance for every dep |

```bash
# Sign a container image with cosign (SLSA Level 2+)
cosign sign --key cosign.key ghcr.io/org/app:v1.2.3

# Verify before deploy
cosign verify --key cosign.pub ghcr.io/org/app:v1.2.3

# Generate SLSA provenance (GitHub Actions)
- uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2
```

### SBOM Generation

Software Bill of Materials — a machine-readable inventory of all components in a build.

**Standard formats:**
- [CycloneDX](https://cyclonedx.org/) — OWASP standard, most widely adopted
- [SPDX](https://spdx.dev/) — ISO standard, used in legal/compliance contexts

```bash
# Generate CycloneDX SBOM (npm)
cyclonedx-bom -o sbom.cdx.json

# Generate SPDX SBOM (Go)
spdx-sbom-generator -p . -o sbom.spdx

# Attach SBOM to container image
cosign attach sbom --sbom sbom.cdx.json ghcr.io/org/app:v1.2.3

# Verify SBOM is present
cosign verify-attestation --type cyclonedx ghcr.io/org/app:v1.2.3
```

### Pipeline Hardening Checklist

- [ ] CI workflows require manual approval before running on forks
- [ ] Secrets are scoped to the minimum permissions needed
- [ ] OIDC-based cloud auth (no static keys in CI)
- [ ] Build artifacts are signed (cosign, sigstore)
- [ ] Container images are scanned in CI before push
- [ ] SBOM is generated and attached to every release
- [ ] Pipeline definitions are version-controlled and reviewed
- [ ] No inline secrets in pipeline YAML files
- [ ] Build runners are ephemeral and do not persist state
- [ ] Dependency versions are pinned and verified (lockfiles, checksums)

---