---
source: "common/security-testing.md"
title: "🔬 Security Testing Methodology"
heading: "1. Testing Types Overview"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, fuzzing, methodology, penetration, testing, tool, types]
chunk: 2/8
---

## 1. Testing Types Overview

```
┌─────────────────────────────────────────────────────────┐
│                    SECURITY TESTING                      │
├────────────┬────────────┬────────────┬──────────────────┤
│    SAST    │    DAST    │    SCA     │       IAST       │
│  Static    │  Dynamic   │ Dependency │  Interactive     │
│  Analysis  │  Analysis  │  Analysis  │  Analysis        │
├────────────┼────────────┼────────────┼──────────────────┤
│ White-Box  │ Black-Box  │   Supply   │  Grey-Box        │
│            │            │   Chain    │  (Runtime+Code)  │
├────────────┼────────────┼────────────┼──────────────────┤
│ Before     │ Before     │ Build &    │  During          │
│ Compile    │ Deploy     │ Monitor    │  Testing         │
└────────────┴────────────┴────────────┴──────────────────┘
```

### SAST (Static Application Security Testing)
- **What**: Analyzes source code without executing it
- **When**: Pre-commit / CI pipeline / IDE
- **False Positives**: Moderate-High (needs triage)
- **Best for**: Finding injection flaws, crypto misuse, hardcoded secrets

### DAST (Dynamic Application Security Testing)
- **What**: Tests running application from the outside
- **When**: Staging/Pre-prod environment
- **False Positives**: Low-Moderate
- **Best for**: Runtime issues, misconfigurations, auth bypass

### SCA (Software Composition Analysis)
- **What**: Scans dependencies for known vulnerabilities
- **When**: Build time + continuous monitoring
- **False Positives**: Low (CVE-based)
- **Best for**: Supply chain security, known CVEs in libs

### IAST (Interactive Application Security Testing)
- **What**: Combines SAST + DAST — instruments the app during functional testing
- **When**: During QA / integration tests
- **False Positives**: Very Low
- **Best for**: Accurate vulnerability detection with low noise

---