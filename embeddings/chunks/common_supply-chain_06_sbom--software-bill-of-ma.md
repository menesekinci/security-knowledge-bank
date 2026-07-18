---
source: "common/supply-chain.md"
title: "Supply Chain Security — Dependency Confusion, Typo-Squatting, Malicious Packages"
heading: "SBOM (Software Bill of Materials)"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common, common-vuln, manager, package, sbom, software, supply, vibe, what]
chunk: 6/10
---

## SBOM (Software Bill of Materials)

An SBOM is a formal, machine-readable inventory of all components in your software. Required by **US Executive Order 14028** for government software.

### Generating an SBOM

```bash
# npm
npm sbom --format=cyclonedx > sbom.json

# Go
go-sbom ./... > sbom.spdx.json

# Python (using CycloneDX)
pip install cyclonedx-bom
cyclonedx-py -i requirements.txt -o sbom.xml

# Generic (using Syft)
syft packages ./myapp --format cyclonedx-json > sbom.json
```

---