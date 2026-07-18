---
source: "languages/javascript/npm-supply-chain.md"
title: "npm Supply Chain Security"
heading: "Real-World Supply Chain Attacks"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World Supply Chain Attacks

| Attack | Year | Method | Impact |
|---|---|---|---|
| **September 2025 npm Attack** | 2025 | 200+ packages compromised via maintainer phishing | Crypto-stealing malware |
| **@redhat-cloud-services** | 2026 | 32 packages under official namespace compromised | Enterprise supply chain |
| **Dependency Confusion Campaign** | 2026 | 33 malicious packages profiling dev environments | Reconnaissance |
| **eslint-scope** | 2018 | Compromised npm credentials on popular package (millions of weekly downloads) | Credential theft |
| **event-stream** | 2018 | Malicious dependency added to copay Bitcoin wallet | Targeted crypto-wallet key theft |
| **ua-parser-js** | 2021 | Maintainer account compromised, malware injected | Credential theft |
| **colors / faker** | 2022 | Maintainer deliberately broke packages | Production outages |
| **node-ipc** | 2022 | Maintainer added protestware deleting files in Russia/Belarus | Data destruction |

---