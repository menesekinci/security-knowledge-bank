# 📚 Resources & References

> Reference sources, security tools, reading lists, and cheat sheets
> for the Vibe Coding Security Knowledge Bank.

---

## 🏛️ Institutional Resources

### OWASP (Open Web Application Security Project)
| Resource | Link | Description |
|----------|------|-------------|
| OWASP Top 10:2021 | https://owasp.org/Top10/ | The 10 most critical security risks for web applications |
| OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/ | Practical security guide for every topic |
| OWASP ASVS | https://owasp.org/www-project-application-security-verification-standard/ | Application security verification standard |
| OWASP API Security Top 10 | https://owasp.org/www-project-api-security/ | The 10 most critical API security risks |
| OWASP Mobile Top 10 | https://owasp.org/www-project-mobile-top-10/ | Mobile application security risks |

### CWE (Common Weakness Enumeration)
| Resource | Link | Description |
|----------|------|-------------|
| CWE Top 25 (2024) | https://cwe.mitre.org/top25/ | The 25 most dangerous software weaknesses |
| CWE Database | https://cwe.mitre.org/ | 900+ weakness categories |

### SANS
| Resource | Link |
|----------|------|
| SANS Top 25 | https://www.sans.org/top25-software-errors/ |
| SANS Secure Coding | https://www.sans.org/secure-coding/ |

---

## 🛠️ Security Tools

### SAST (Static Analysis)
| Tool | Language | Description |
|------|----------|-------------|
| **Semgrep** | Multi-language | Rule-based static analysis, 2000+ rules |
| **CodeQL** | Multi-language | GitHub's query-based security analysis |
| **SonarQube** | Multi-language | Comprehensive code quality + security |
| **Bandit** | Python | Python security linter |
| **Brakeman** | Ruby | Ruby on Rails security scanner |
| **FindSecBugs** | Java | Java/Spring security scanning |
| **SpotBugs** | Java | Java bug patterns |
| **Clippy** | Rust | Rust security linting |
| **gosec** | Go | Go security scanner |
| **phpstan-pro** | PHP | PHP static analysis |

### DAST (Dynamic Analysis)
| Tool | Description |
|------|-------------|
| **OWASP ZAP** | Web application penetration test tool |
| **Burp Suite** | Professional web security testing platform |
| **Nuclei** | Template-based vulnerability scanner |
| **Nikto** | Web server scanner |

### SCA (Software Composition Analysis)
| Tool | Ecosystem | Description |
|------|-----------|-------------|
| **Dependabot** | GitHub | Automatic dependency update + security alert |
| **Snyk** | Multi-language | Container + dependency security scanning |
| **Renovate** | Multi-language | Automatic dependency update bot |
| **`pip-audit`** | Python | PyPI dependency scanning |
| **`cargo-audit`** | Rust | Rust dependency scanning |
| **`npm audit`** | Node.js | npm dependency scanning |
| **Trivy** | Multi-language | Container + repo + dependency scanning |
| **Grype** | Multi-language | Fast vulnerability scanner |

### Supply Chain
| Tool | Description |
|------|-------------|
| **sigstore/cosign** | Software signing and verification |
| **SLSA Framework** | Supply chain security levels |
| **in-toto** | Supply chain integrity |
| **guac** | Supply chain metadata collection |

### Secret Detection
| Tool | Description |
|------|-------------|
| **GitGuardian** | Secret leak detection |
| **truffleHog** | Secret scanning in Git history |
| **Gitleaks** | Git repo secret scanner |
| **git-secrets** | Secret blocking via pre-commit hook |

---

## 📖 Vibe Coding Security Reading List

### AI Code Generation and Security
1. [Stanford HAI: AI coding assistants introduce more security vulnerabilities](https://hai.stanford.edu/)
2. [GitLab: AI-generated code needs more human review](https://about.gitlab.com/)
3. [Snyk: AI Code Security Report 2024](https://snyk.io/)
4. [OWASP: AI Security and Privacy Guide](https://owasp.org/www-project-ai-security-and-privacy-guide/)
5. [CVE Program: Known vulnerabilities database](https://cve.mitre.org/)

### Prompt Engineering
1. [Learn Prompting: Prompt Injection](https://learnprompting.org/docs/prompt_injection)
2. [OWASP: Prompt Injection Cheat Sheet](https://github.com/OWASP/www-project-ai-security-and-privacy-guide)

---

## 🔗 Cross-Reference Index

| Topic in This Bank | OWASP Mapping | CWE ID |
|-------------------|---------------|--------|
| Injection | A03:2021 | CWE-79, CWE-89, CWE-73 |
| Broken Auth | A07:2021 | CWE-287, CWE-798 |
| XSS | A03:2021 | CWE-79 |
| Deserialization | (A08:2017) | CWE-502 |
| Crypto Failures | A02:2021 | CWE-327, CWE-328 |
| IDOR | A01:2021 | CWE-639 |
| Misconfiguration | A05:2021 | CWE-16 |
| SSRF | A10:2021 | CWE-918 |
| Path Traversal | - | CWE-22, CWE-23 |
| Race Conditions | - | CWE-362, CWE-367 |
| Supply Chain | - | CWE-1104 |
| Memory Safety | - | CWE-119, CWE-787 |
| Business Logic | A01:2021 | CWE-840 |
| Logging | A09:2021 | CWE-778 |
| SSTI | A03:2021 | CWE-1336 |
| Mass Assignment | A01:2021 | CWE-915 |
| ReDoS | - | CWE-1333 |
| Open Redirect | - | CWE-601 |
| Prototype Pollution | - | CWE-1328 |

---

> *Last updated: July 2026*
