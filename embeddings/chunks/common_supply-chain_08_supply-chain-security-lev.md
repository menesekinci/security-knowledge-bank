---
source: "common/supply-chain.md"
title: "Supply Chain Security — Dependency Confusion, Typo-Squatting, Malicious Packages"
heading: "Supply Chain Security Levels"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common, common-vuln, manager, package, sbom, software, supply, vibe, what]
chunk: 8/10
---

## Supply Chain Security Levels

| Level | Practices |
|---|---|
| **🥇 Level 3** | SBOM generation, artifact signing, dependency review, runtime monitoring, SLSA Level 3+ |
| **🥈 Level 2** | Lockfiles, version pinning, automated scanning, private registry, Dependabot |
| **🥉 Level 1** | Lockfiles, `npm audit`, known vuln scanning |
| **❌ None** | No lockfiles, wide version ranges, no scanning |

---