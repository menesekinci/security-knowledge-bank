---
source: "languages/python/supply-chain-deep.md"
title: "PyPI Supply Chain Security: Deep Dive"
heading: "Real Attack Timeline (2024-2025)"
category: "language-vuln"
language: "python"
severity: "high"
tags: [attack, language-vuln, overview, python, vector]
chunk: 8/10
---

## Real Attack Timeline (2024-2025)

| Date | Attack | Impact | Discovery |
|------|--------|--------|-----------|
| Jan 2024 | Typosquatting campaign mimicking 20+ ML packages | API key theft | Checkmarx |
| Mar 2024 | `colorama` typosquatting (17 packages) | Developer credential theft | Checkmarx |
| Jul 2024 | Dependency confusion on `aws-cdk` variants | CI/CD token theft | AWS Security |
| Sep 2024 | PyPI account takeover via session hijacking | 3 packages backdoored | PyPI Security |
| Nov 2024 | AI/ML SDK impersonation (TeamPCP) | Training data exfiltration | Cloud Security Alliance |
| Mar 2025 | LiteLLM maintainer account compromise | AI API key theft | CQURE |
| Jun 2025 | `alibaba-ai-sdk` typosquatting | Credential exfiltration | Cloud Security Alliance |

---