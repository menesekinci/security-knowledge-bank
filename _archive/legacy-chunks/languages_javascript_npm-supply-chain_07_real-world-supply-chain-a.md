---
source: "languages/javascript/npm-supply-chain.md"
title: "npm Supply Chain Security"
category: "language-vuln"
language: "javascript"
chunk: 7
total_chunks: 8
heading: "Real-World Supply Chain Attacks"
---

## Real-World Supply Chain Attacks

| Attack | Year | Method | Impact |
|---|---|---|---|
| **September 2025 npm Attack** | 2025 | 200+ packages compromised via maintainer phishing | Crypto-stealing malware |
| **@redhat-cloud-services** | 2026 | 32 packages under official namespace compromised | Enterprise supply chain |
| **Dependency Confusion Campaign** | 2026 | 33 malicious packages profiling dev environments | Reconnaissance |
| **eslint-scope** | 2018 | Compromised npm credentials on popular package (80k+ weekly downloads) | Credential theft |
| **event-stream** | 2018 | Malicious dependency added to copay Bitcoin wallet | Crypto theft ($8M+) |
| **ua-parser-js** | 2021 | Maintainer account compromised, malware injected | Credential theft |
| **colors / faker** | 2022 | Maintainer deliberately broke packages | Production outages |
| **node-ipc** | 2022 | Maintainer added protestware deleting files in Russia/Belarus | Data destruction |

---