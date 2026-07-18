---
source: "languages/javascript/npm-supply-chain.md"
title: "npm Supply Chain Security"
category: "language-vuln"
language: "javascript"
chunk: 8
total_chunks: 8
heading: "Vibe Coding Red Flags"
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