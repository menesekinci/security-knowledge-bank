# 🚀 CI/CD Security (Secure CI/CD Pipeline)

> **Category:** Common / CI/CD Security
> **Last Updated:** July 2026
> **Description:** Comprehensive guide to securing CI/CD pipelines for AI-generated code. Covers pipeline security, secret scanning, dependency scanning, artifact signing, and SBOM generation.

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

## 2. Secret Scanning in CI

### Tools

| Tool                 | Language/Scope              | Integration          |
|----------------------|-----------------------------|----------------------|
| **Gitleaks**         | Multi-language              | Pre-commit, CI       |
| **truffleHog**       | Multi-language (regex+entropy) | CI, post-commit   |
| **GitHub Secret Scanning** | GitHub repos           | Native (push events) |
| **GitLab Secret Detection** | GitLab repos          | Native (CI jobs)     |
| **detect-secrets**   | Multi-language              | Pre-commit, CI       |
| **Semgrep Secrets**  | Multi-language (semantic)   | CI, pre-commit       |

### CI Configuration — Gitleaks (GitHub Actions)

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### What to Scan For

```yaml
# .gitleaks.toml — custom rules for AI-generated code
[secrets]
# API keys, tokens, passwords
description = "Generic API Key"
regex = '''(?i)(?:api[_-]?key|secret|token|password|credential|auth).{0,30}['\"][0-9a-zA-Z]{16,}'''
 
description = "Private Key"
regex = '''-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'''
 
description = "JWT Token"
regex = '''eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'''

# AI-specific: hallucinated credentials
description = "AI Test Credential"
regex = '''(?:test|example|demo|sample|placeholder)_?(?:key|secret|password|token).{0,10}(?:test|example|1234|changeme)'''
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
```

---

## 3. Dependency Scanning in Build

### Tool Integration

**npm/yarn (JS/TS):**
```yaml
- run: npm audit --audit-level=high
- run: npm ls --depth=0  # verify installed versions
```

**pip (Python):**
```yaml
- run: pip-audit --strict  # fail on any known vuln
```

**Go:**
```yaml
- run: govulncheck ./...
```

**Rust:**
```yaml
- run: cargo audit
```

**Java/Maven:**
```yaml
- run: mvn org.owasp:dependency-check-maven:check
```

**Universal (containers):**
```yaml
- uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'fs'
    scan-ref: '.'
    format: 'sarif'
    output: 'trivy-results.sarif'
    exit-code: '1'
```

### Dependency Scanning CI Gate

```yaml
# .github/workflows/dep-scan.yml
name: Dependency Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      
      # Language-specific scans
      - name: Scan npm packages
        if: hashFiles('package-lock.json') != ''
        run: |
          npm audit --audit-level=high
          
      - name: Scan Go modules
        if: hashFiles('go.sum') != ''
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...
          
      - name: Scan Python deps
        if: hashFiles('requirements.txt', 'Pipfile.lock') != ''
        run: pip-audit --strict
        
      # Container-level scan
      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
```

### Preventing Dependency Confusion

```yaml
# .npmrc — prevent typosquatting/dependency confusion
registry=https://registry.npmjs.org/
@my-company:registry=https://npm.pkg.github.com

# GitHub Actions: check package origin
- name: Check for dependency confusion
  run: |
    # Ensure private packages resolve to private registry
    npm ls @my-company/ --depth=0 --all 2>&1 | grep -v "github.com" && exit 1 || true
```

---

## 4. Artifact Signing

### Why Sign Artifacts?

- **Integrity**: Detect tampering between build and deploy
- **Provenance**: Prove who/what created the artifact
- **Non-repudiation**: Publisher cannot deny signing the release

### Tools

| Tool             | Standard         | Best For                |
|------------------|------------------|-------------------------|
| **Sigstore Cosign** | OIDC-based    | Container images, blobs |
| **GPG**          | PGP              | Git tags, traditional   |
| **minisign**     | Ed25519          | Lightweight, small bins |
| **notary**       | TUF framework    | Large-scale OTA updates |

### Cosign — Signing Container Images (CI)

```yaml
- name: Sign container image
  env:
    COSIGN_EXPERIMENTAL: 1  # keyless signing
  run: |
    cosign sign --yes ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.digest.outputs.digest }}
```

### GPG — Signing Git Tags

```bash
# Configure signing
git config --global user.signingkey ABCDEF1234567890
git config --global commit.gpgsign true

# Sign a release
git tag -s v1.0.0 -m "Release v1.0.0"
git verify-tag v1.0.0
```

### Cosign — Verifying in CI

```yaml
- name: Verify signed artifact
  run: |
    cosign verify \
      --certificate-identity-regexp '^https://github.com/my-org/' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.digest.outputs.digest }}
```

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

## References

- [SLSA Framework](https://slsa.dev/)
- [Sigstore / Cosign](https://www.sigstore.dev/)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/SBOM)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Gitleaks](https://gitleaks.io/)
- [Trivy](https://trivy.dev/)
- [GitHub Security Best Practices](https://docs.github.com/en/actions/security-guides)
- [Supply-chain Levels for Software Artifacts](https://slsa.dev/spec/v1.0/)
- [EO 14028 — Improving the Nation's Cybersecurity](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)
