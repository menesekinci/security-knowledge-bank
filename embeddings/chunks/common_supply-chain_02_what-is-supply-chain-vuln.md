---
source: "common/supply-chain.md"
title: "Supply Chain Security — Dependency Confusion, Typo-Squatting, Malicious Packages"
heading: "What Is Supply Chain Vulnerability?"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common, common-vuln, manager, package, sbom, software, supply, vibe, what]
chunk: 2/10
---

## What Is Supply Chain Vulnerability?

Supply chain attacks target the **trust relationship** between your application and its dependencies — the open-source packages, libraries, container images, and third-party services you rely on. Attackers compromise these dependencies to inject malicious code into your application.

**The impact:** Remote code execution, data exfiltration, backdoors, credential theft. A single compromised dependency can affect thousands of downstream applications.