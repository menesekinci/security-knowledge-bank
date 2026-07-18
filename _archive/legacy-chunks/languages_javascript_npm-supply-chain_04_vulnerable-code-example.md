---
source: "languages/javascript/npm-supply-chain.md"
title: "npm Supply Chain Security"
category: "language-vuln"
language: "javascript"
chunk: 4
total_chunks: 8
heading: "Vulnerable Code Example"
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