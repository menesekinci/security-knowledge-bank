---
source: "common/supply-chain.md"
title: "Supply Chain Security — Dependency Confusion, Typo-Squatting, Malicious Packages"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common, common-vuln, manager, package, sbom, software, supply, vibe, what]
chunk: 7/10
---

## Prevention Checklist for AI Prompts

```
✅ SUPPLY CHAIN REQUIREMENTS FOR THIS CODE:
- Pin exact dependency versions (no ^ or ~ ranges unless necessary)
- Always use lockfiles (package-lock.json, yarn.lock, Cargo.lock, go.sum)
- Verify package names carefully — watch for typo-squatting
- Use private registry with auth for internal packages
- Register all possible namespace variations of internal packages
- Run npm audit, pip-audit, or equivalent before each deployment
- Use dependency scanning tools (Snyk, Dependabot, Renovate, Socket.dev)
- Sign and verify release artifacts
- Maintain an SBOM for every release
- Review dependency licenses and maintainer reputation
- Use minimal base Docker images (distroless, Alpine)
- Don't install dev dependencies in production
- Set up binary repository manager (Nexus, Artifactory) for dependency caching
- Monitor CVE databases for all direct and transitive dependencies
```

### Automated Tooling

| Tool | Purpose |
|---|---|
| Dependabot / Renovate | Automated dependency updates |
| Snyk / Socket.dev | Vulnerability scanning + malware detection |
| npm audit / pip-audit | Registry-published vulnerability check |
| Trivy / Grype | Container and filesystem scanning |
| Syft | SBOM generation |
| Sigstore / Cosign | Artifact signing |
| OWASP Dependency-Check | Comprehensive dependency analysis |
| OpenSSF Scorecard | Evaluate open-source project security practices |

---