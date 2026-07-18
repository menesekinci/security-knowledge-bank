---
source: "common/secure-cicd.md"
title: "🚀 CI/CD Security (Secure CI/CD Pipeline)"
heading: "3. Dependency Scanning in Build"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [artifact, common-vuln, dependency, generation, pipeline, sbom, scanning, secret, security, signing]
chunk: 4/9
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