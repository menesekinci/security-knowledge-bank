---
source: "common/security-testing.md"
title: "🔬 Security Testing Methodology"
heading: "2. Tool Per Language Matrix"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, fuzzing, methodology, penetration, testing, tool, types]
chunk: 3/8
---

## 2. Tool Per Language Matrix

| Language   | SAST                          | DAST                  | SCA                                    | IAST                   |
|------------|-------------------------------|-----------------------|----------------------------------------|------------------------|
| **Python** | Bandit, Semgrep, Ruff         | OWASP ZAP, Nuclei     | pip-audit, Safety, Trivy               | Contrast, Hdiv         |
| **JS/TS**  | ESLint w/ security plugin, CodeQL, semgrep | ZAP, Burp            | npm audit, yarn audit, Snyk, Socket    | Contrast, Seeker       |
| **Java**   | SpotBugs + FindSecBugs, Semgrep, Checkstyle | ZAP, Burp, AppScan   | OWASP Dependency-Check, Snyk, Trivy    | Contrast, Seeker       |
| **Go**     | gosec, Semgrep, Staticcheck   | ZAP, Nuclei           | govulncheck, Trivy, Snyk               | Contrast               |
| **Rust**   | Clippy, cargo-audit, Semgrep  | ZAP, custom fuzzing   | cargo-audit, cargo-deny                | Limited                |
| **Ruby**   | Brakeman, Semgrep, RuboCop    | ZAP, Nuclei           | bundler-audit, Trivy                   | Contrast               |
| **C#/.NET**| SecurityCodeScan, Roslyn, Semgrep | ZAP, Burp          | dotnet list pkg --vulnerable, Trivy    | Contrast               |
| **PHP**    | PHPStan (pro), Psalm, Semgrep | ZAP, WPScan, Nuclei   | composer audit, Trivy                  | Contrast               |
| **C/C++**  | Clang Static Analyzer, Cppcheck, CodeQL | Custom fuzzing | Snyk, Trivy (OS libs)                  | Limited                |
| **Swift**  | SwiftLint, Semgrep, CodeQL    | ZAP (API), MobSF      | SPM audit, Trivy                       | Limited                |
| **Kotlin** | detekt, Semgrep, Android Lint | MobSF, ZAP            | OWASP Dependency-Check, Trivy          | Contrast               |
| **Solidity**| Slither, Mythril, Semgrep    | Custom fuzzing (Echidna, Foundry) | —                     | —                      |

---