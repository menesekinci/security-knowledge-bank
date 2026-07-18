---
source: "common/supply-chain.md"
title: "Supply Chain Security — Dependency Confusion, Typo-Squatting, Malicious Packages"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common, common-vuln, manager, package, sbom, software, supply, vibe, what]
chunk: 3/10
---

## Why Vibe Coding Makes This Worse

AI code generators amplify supply chain risk in several ways:

- **AI recommends packages without vetting:** "Use package X" — but AI doesn't check if X has 10M downloads or 10 downloads (typo-squatting risk)
- **AI uses latest-version syntax:** Generates code that requires bleeding-edge versions that may not exist yet
- **AI writes npm/pip install commands:** Could suggest installing packages from suspicious sources
- **No lockfile management:** AI doesn't generate or explain the importance of `package-lock.json`, `requirements.txt` with hashes, or `go.sum`
- **Copy-paste from internet:** AI frequently generates code copied from Stack Overflow or GitHub gists — which attackers have been known to poison

---