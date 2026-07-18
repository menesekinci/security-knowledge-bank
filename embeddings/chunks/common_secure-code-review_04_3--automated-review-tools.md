---
source: "common/secure-code-review.md"
title: "🔍 Secure Code Review Checklist"
heading: "3. Automated Review Tools"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [ai-generated, automated, common-vuln, flags, language-specific, review, reviewing, security]
chunk: 4/8
---

## 3. Automated Review Tools

### SAST Tools (Run in CI)

| Tool               | Languages              | Key Strengths                       |
|--------------------|------------------------|-------------------------------------|
| **Semgrep**        | 30+ languages          | Custom rules, high signal-to-noise  |
| **CodeQL**         | C/C++, C#, Go, Java, JS/TS, Python | Deep data flow analysis |
| **GitHub Code Scanning** | Multi-language   | Integrated with PR checks           |
| **SonarQube**      | 30+ languages          | Quality + security, tech debt       |
| **Brakeman**       | Ruby on Rails          | Rails-specific, low false positives |
| **Bandit**         | Python                 | Security-focused, simple rules      |
| **gosec**          | Go                     | Go-specific security patterns       |
| **Clippy**         | Rust                   | Lint + some security checks         |
| **detekt**         | Kotlin                 | Kotlin-specific static analysis     |
| **SecurityCodeScan**| C#                    | .NET security patterns              |
| **Slither**        | Solidity               | Smart contract vulnerabilities      |

### Secret Detection

| Tool                 | Scope             | CI Integration |
|----------------------|-------------------|----------------|
| **Gitleaks**         | Git history       | ✅ Pre-commit + CI |
| **truffleHog**       | Git + filesystem  | ✅ CI           |
| **GitHub Secret Scanning**| GitHub repos| ✅ Native       |
| **GitGuardian**      | API + CLI         | ✅ CI + Portal  |

### Dependency Scanners

| Tool                 | Scope              | CI Integration |
|----------------------|--------------------|----------------|
| **Trivy**            | All ecosystems     | ✅ Container + FS |
| **Snyk**             | Multi-language     | ✅ CI + CLI     |
| **npm audit**        | JS/TS              | ✅ CI           |
| **cargo audit**      | Rust               | ✅ CI           |
| **pip-audit**        | Python             | ✅ CI           |
| **govulncheck**      | Go                 | ✅ CI           |
| **OWASP Dependency-Check**| Java/.NET    | ✅ CI           |

### AI-Assisted Code Review Tools

| Tool                   | What It Does                                   |
|------------------------|------------------------------------------------|
| **GitHub Copilot Code Review** | AI-powered PR review suggestions     |
| **CodeRabbit**         | AI code review with security focus             |
| **SonarQube AI**       | AI-assisted issue detection                   |
| **Semgrep Pro**        | Interfile analysis + AI-powered prioritization |
| **Socket**             | AI-driven supply chain risk detection         |

---