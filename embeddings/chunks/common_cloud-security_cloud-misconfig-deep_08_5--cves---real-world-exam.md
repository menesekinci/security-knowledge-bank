---
source: "common/cloud-security/cloud-misconfig-deep.md"
title: "Cloud Misconfiguration Deep Dive"
heading: "5. CVEs & Real-World Examples"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud, cloud-security, credential, environment, overview, table, variable]
chunk: 8/9
---

## 5. CVEs & Real-World Examples

### CVE-2025-30066 — GitHub Actions Supply Chain Attack (tj-actions/changed-files)
- **Description**: In March 2025, the popular GitHub Action `tj-actions/changed-files` was compromised. The attacker modified existing version tags to include malicious code that exfiltrated CI/CD secrets (cloud credentials, API keys, deployment tokens) from workflow logs to an external server
- **Impact**: Over 23,000 repositories potentially had their cloud credentials stolen
- **The attack chain**: GitHub Action compromised → read `secrets` context from workflow → exfiltrated via HTTP POST → attackers accessed cloud infrastructure
- **CVSS**: 9.1 (Critical)
- **Fix**: Rotate all secrets used in workflows; audit workflow logs; pin actions by commit hash (not semver tags)
- **Source**: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066

### CISA AWS GovCloud Credential Leak (2025)
- **Description**: A CISA administrator accidentally exposed AWS GovCloud plaintext credentials in a private GitHub repository. The `.gitignore` was missing from the repo, and the credentials file was committed. Automated scanners found the credentials within days, even though the repo was private
- **Impact**: AWS GovCloud — the US government's isolated cloud — had admin-level credentials publicly exposed
- **CVSS**: 9.8 (Critical)
- **Fix**: git-secrets scanning; proper `.gitignore`; rotate all GovCloud credentials
- **Source**: https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/

### Claude Code CLI — Three CVEs in 2025 (Shell Injection to Exfiltration)
- **Description**: Security researcher RyotaK discovered three CVEs in Anthropic's Claude Code CLI tool (CVE-2025-XXXX series). Attackers could craft prompts leading to shell injection, which exfiltrated cloud credentials from the developer's environment. This demonstrated the risk of AI coding assistants having filesystem and network access
- **Impact**: Cloud credentials accessed via AI assistant's shell execution
- **Fix**: Restrict AI assistant permissions; audit shell commands; use sandbox environments
- **Source**: https://phoenix.security/claude-code-leak-to-vulnerability-three-cves-in-claude-code-cli-and-the-chain-that-connects-them/

### Claude Code git Credential Helper CVEs (2024-2025)
- **Description**: A cluster of CVEs discovered in Git's credential helper mechanism. Researchers found that AI coding tools (including Claude Code and Copilot) could be tricked into leaking stored git credentials through crafted prompts
- **Affected**: Git credential helpers, multiple AI coding tools
- **Fix**: Use fine-grained access tokens; prompt-block sensitive operations; audit AI tool requests
- **Source**: https://phoenix.security/claude-code-leak-to-vulnerability-three-cves-in-claude-code-cli-and-the-chain-that-connects-them/

### "Vibe Coding's Security Debt" — Cloud Security Alliance (2026)
- **Description**: The Cloud Security Alliance published a research note documenting a 400% increase in cloud misconfiguration vulnerabilities traced to AI-generated code from 2024 to 2026. Key finding: 45% of AI-generated cloud configuration samples introduce OWASP Top 10 vulnerabilities — a pass rate that has not improved across multiple testing cycles
- **Impact**: Systemic insecurity in infrastructure-as-code
- **Fix**: AI-generated code must pass through security scanning before deployment
- **Source**: https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-generated-code-vulnerability-surge-2026/

### 28 Million Secrets on GitHub in 2025 (Snyk State of Secrets)
- **Description**: Snyk's 2025 report documented that 28 million credentials were leaked on GitHub in a single year — a 5x increase from 2023. Key finding: AI-assisted commits are 3x more likely to contain hardcoded credentials than manually-written commits
- **Impact**: Widespread cloud account compromise
- **Fix**: Git hooks; secret scanning; AI assistant security training; pre-commit detection
- **Source**: https://snyk.io/articles/state-of-secrets/

---