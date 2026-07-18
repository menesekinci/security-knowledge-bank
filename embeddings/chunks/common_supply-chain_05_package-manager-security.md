---
source: "common/supply-chain.md"
title: "Supply Chain Security — Dependency Confusion, Typo-Squatting, Malicious Packages"
heading: "Package Manager Security Comparison"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common, common-vuln, manager, package, sbom, software, supply, vibe, what]
chunk: 5/10
---

## Package Manager Security Comparison

| Manager | Lockfile | Integrity Check | Sig Verification | SBOM Support |
|---|---|---|---|---|
| **npm** | `package-lock.json` | ✅ Subresource Integrity | ❌ (proposal) | ✅ (via `npm sbom`) |
| **yarn** | `yarn.lock` | ✅ Checksum | ❌ | ✅ |
| **pnpm** | `pnpm-lock.yaml` | ✅ Checksum | ❌ | ✅ |
| **pip** | `requirements.txt` + hashes | ✅ via `--hash` | ❌ | ✅ (via pip-audit) |
| **Poetry** | `poetry.lock` | ✅ | ❌ | ✅ |
| **Go Modules** | `go.sum` | ✅ Checksum | ✅ (sumdb) | ✅ |
| **Cargo (Rust)** | `Cargo.lock` | ✅ Checksum | ❌ | ✅ |
| **Maven/Gradle** | (effective) | ✅ Checksum | ✅ (GPG) | ✅ (CycloneDX) |

---