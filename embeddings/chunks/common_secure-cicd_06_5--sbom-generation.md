---
source: "common/secure-cicd.md"
title: "🚀 CI/CD Security (Secure CI/CD Pipeline)"
heading: "5. SBOM Generation"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [artifact, common-vuln, dependency, generation, pipeline, sbom, scanning, secret, security, signing]
chunk: 6/9
---

## 5. SBOM Generation

### What is an SBOM?

A **Software Bill of Materials** is a machine-readable inventory of all components in a software artifact. Required by:
- **EO 14028** (US Executive Order on Cybersecurity)
- **NTIA** Minimum Elements for SBOM
- **PCI DSS v4.0** (software security framework)
- **ISO 5230** (OpenChain)

### SBOM Formats

| Format   | Standard            | Tool Support                 |
|----------|---------------------|------------------------------|
| SPDX     | ISO/IEC 5962:2021   | Trivy, Syft, ORT            |
| CycloneDX| OWASP               | Trivy, Syft, CycloneDX CLI  |

### Generating SBOM in CI

```yaml
# Generate SBOM with Syft
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    path: ./
    format: spdx-json
    output-file: sbom.spdx.json

# Upload SBOM as build artifact
- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.spdx.json
```

### SBOM with Trivy

```yaml
- name: Generate CycloneDX SBOM
  run: |
    trivy filesystem --format cyclonedx \
      --output sbom.cdx.json \
      .

# Verify SBOM against vulnerabilities
- name: Check SBOM for vulns
  run: |
    trivy sbom sbom.cdx.json --exit-code 1 --severity CRITICAL,HIGH
```

### SBOM Attestation with Sigstore

```yaml
# Sign the SBOM itself
- name: Attest SBOM
  run: |
    cosign attest-blob sbom.spdx.json \
      --predicate sbom.spdx.json \
      --type spdx \
      --yes
```

---