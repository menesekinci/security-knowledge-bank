---
source: "languages/python/dependency-safety.md"
title: "Dependency Safety — Python Supply Chain"
heading: "Real-World Supply Chain Attacks"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World Supply Chain Attacks

| Attack | Year | Method | Impact |
|---|---|---|---|
| **PyTorch Dependency Confusion** | 2022 | Attacker registered `pytorch` on PyPI (different from `torch`) | Code execution in CI |
| **ctx / phpass** | 2023 | Malicious packages on PyPI stealing AWS keys | Credential theft |
| **Colourama** | 2023 | Typo-squatting `colorama` | Malware distribution |
| **Requests Typosquatting** | 2023 | Packages like `requestts`, `reqests` | Credential theft |
| **PyPI Malicious Package Flood** | 2024 | 200+ packages with dependency confusion names | Supply chain compromise |
| **September 2025 npm** | 2025 | 200+ packages compromised via maintainer account takeover | Similar patterns apply to PyPI |
| **2026 npm Dependency Confusion** | 2026 | 33 malicious npm packages profiling dev environments | Reconnaissance |

---