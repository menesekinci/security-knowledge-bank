---
source: "languages/javascript/npm-supply-chain.md"
title: "npm Supply Chain Security"
category: "language-vuln"
language: "javascript"
chunk: 5
total_chunks: 8
heading: "Secure Code Fix"
---

## Secure Code Fix

### Fix 1: Pin Exact Versions and Use Lockfiles

```json
// ✅ SAFE — Pinned versions in package.json
{
  "dependencies": {
    "express": "4.18.2",            // No ^ or ~ — exact version
    "react": "18.2.0",
    "lodash": "4.17.21",
    "jsonwebtoken": "9.0.2"
  }
}
```

```bash
# ✅ SAFE — Generate and commit lockfile
npm install --save-exact --package-lock
git add package-lock.json
```

### Fix 2: Use npm audit and Lockfile Validation

```bash
# ✅ SAFE — CI/CD dependency scanning
npm audit --audit-level=high          # Fail on high severity
npm audit --audit-level=critical      # Fail on critical only

# Yarn audit
yarn audit --level high
```

### Fix 3: Use .npmrc for Security Hardening

```ini
# ✅ SAFE — .npmrc production security settings
# Prevent package.json typosquatting
engine-strict=true
scripts-prepend-node-path=true

# Lockfile verification
package-lock=true
save-exact=true

# Registry security
registry=https://registry.npmjs.org/
@my-company:registry=https://npm.internal.company.com/

# Prevent untrusted installs
ignore-scripts=false  # Review scripts before disabling
```

### Fix 4: Dependency Confusion Prevention

```bash
# ✅ SAFE — Scope all internal packages
# .npmrc
@mycompany:registry=https://npm.internal.company.com/
# This ensures @mycompany/* packages are ONLY fetched from the private registry

# Or use overrides in package.json (npm v8+)
{
  "overrides": {
    "express": "4.18.2",  // Lock transitive dependency
    "request": false       // Remove vulnerable dep entirely
  }
}
```

### Fix 5: CI/CD Package Verification

```yaml
# ✅ SAFE — GitHub Actions npm audit
name: npm Security
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
      - run: npm ci                          # Clean install from lockfile
      - run: npm audit --audit-level=high    # Fail on high+ vulns
      - run: |
          npx lockfile-lint --path package-lock.json \
            --allowed-hosts npm \
            --allowed-schemes https:
      - name: Check for typo-squatting
        run: |
          npm doctor  # npm built-in health check
```

### Fix 6: Use Socket for Proactive Detection

```bash
# ✅ SAFE — Socket.dev detects risky packages before install
npx socket install express  # Scans before installing
# Or use GitHub app for automatic PR scanning
```

### Fix 7: Review package.json Scripts

```json
// ✅ SAFE — Minimal scripts with no postinstall
{
  "scripts": {
    "start": "node server.js",
    "test": "jest",
    "build": "webpack"
  }
  // No "postinstall", "preinstall", "prepublish", etc.
}
```

---