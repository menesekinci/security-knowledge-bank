---
source: "common/secure-cicd.md"
title: "🚀 CI/CD Security (Secure CI/CD Pipeline)"
heading: "6. CI/CD Security for AI-Generated Code"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [artifact, common-vuln, dependency, generation, pipeline, sbom, scanning, secret, security, signing]
chunk: 7/9
---

## 6. CI/CD Security for AI-Generated Code

### Unique Risks

| Risk                          | Description                                 | Mitigation                          |
|-------------------------------|---------------------------------------------|-------------------------------------|
| **Hallucinated packages**     | AI imports packages that don't exist        | SCA + npm audit every build         |
| **Security header removal**   | AI may strip CSP, HSTS for "testing"        | SAST rule enforcement               |
| **Incorrect sig verification**| AI writes verification that always passes   | Review signing code manually        |
| **Build config injection**    | AI-generated config allows PR code execution| Pin runner versions, validate YAML  |
| **Test-only secrets in prod** | AI leaves test keys in production build     | Secret scanning before every deploy |
| **Skipped security steps**    | AI's generated pipeline omits security gates| Template-based pipeline with gates  |

### Secure Pipeline Template

```yaml
# .github/workflows/secure-pipeline.yml
name: Secure CI Pipeline
on: [pull_request, push]

jobs:
  # Gate 1: Secret Scanning
  secret-scan:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2

  # Gate 2: SAST
  sast:
    runs-on: ubuntu-22.04
    needs: [secret-scan]
    steps:
      - uses: actions/checkout@v4
      - name: Run Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: p/default

  # Gate 3: Dependency Scan
  dep-scan:
    runs-on: ubuntu-22.04
    needs: [secret-scan]
    steps:
      - uses: actions/checkout@v4
      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'

  # Gate 4: Build + Sign
  build:
    runs-on: ubuntu-22.04
    needs: [sast, dep-scan]
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: |
          # build command goes here
          make build
      - name: Sign artifact
        run: |
          cosign sign-blob --key env://COSIGN_PRIVATE_KEY output.bin > output.bin.sig

  # Gate 5: SBOM Generation
  sbom:
    runs-on: ubuntu-22.04
    needs: [build]
    steps:
      - uses: actions/checkout@v4
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: spdx-json
          output-file: sbom.spdx.json
      - name: Attest SBOM
        run: |
          cosign attest-blob sbom.spdx.json \
            --predicate sbom.spdx.json --type spdx --yes

  # Gate 6: DAST (on deploy target)
  dast:
    runs-on: ubuntu-22.04
    needs: [build]
    steps:
      - name: Run ZAP scan
        uses: zaproxy/action-full-scan@v0
        with:
          target: ${{ vars.STAGING_URL }}
```

---