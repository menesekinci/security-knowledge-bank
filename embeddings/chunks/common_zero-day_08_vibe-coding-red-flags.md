---
source: "common/zero-day.md"
title: "Zero-Day Vulnerabilities (0-day) and Patch Lag (n-day)"
heading: "Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe-Coding Red Flags

| Red flag | Risk |
|----------|------|
| AI pins packages from a 2019 blog post | Instant n-day debt |
| CI green with `continue-on-error: true` on audit | Policy theater |
| “We’ll upgrade Log4j later” in generated TODO | Classic lag pattern |
| Model invents a CVE number or fake patched version | False confidence |
| Downgrade dependency to fix build errors | Often reintroduces fixed CVEs |
| No SBOM in release artifacts | Cannot answer “are we affected?” in 1 hour |
| Only reading Twitter PoCs, not applying vendor patches | Wrong control plane |
| Assuming WAF alone “fixed Log4Shell” | Incomplete mitigation history repeated |
| AI claims code is safe because “modern framework” | Frameworks still pull vulnerable transitive deps |
| Copying exploit snippets into test suites in prod CI | Dangerous and unnecessary for verification |

**Bottom line:** Zero-days are a **time dimension** of risk. Most catastrophic internet incidents that “felt like zero-days” to victims were **n-days with brutal patch lag**. AI accelerates code and dependency sprawl; pair every AI coding workflow with SCA, patch SLOs, and ruthless inventory — and never ask models for exploit PoCs when the goal is defense.

---

*KB level: L1 common · Topic: 0-day vs n-day · No exploit PoCs · Pair with: supply-chain.md, secure-cicd.md, incident-response.md*