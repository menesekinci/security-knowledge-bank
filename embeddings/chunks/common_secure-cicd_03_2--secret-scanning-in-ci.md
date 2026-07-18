---
source: "common/secure-cicd.md"
title: "🚀 CI/CD Security (Secure CI/CD Pipeline)"
heading: "2. Secret Scanning in CI"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [artifact, common-vuln, dependency, generation, pipeline, sbom, scanning, secret, security, signing]
chunk: 3/9
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