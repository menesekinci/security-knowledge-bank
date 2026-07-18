---
source: "languages/javascript/case-studies/ua-parser-js-2021-supply-chain.md"
title: "npm ua-parser-js (2021) — JavaScript Supply Chain"
category: "case-study"
language: "javascript"
severity: "critical"
tags: [case-study, cause, happened, impact, javascript, root, system, target, what, when]
---

# npm ua-parser-js (2021) — JavaScript Supply Chain

## 📅 When Did It Happen?
October 2021

## 🎯 Target System
npm — `ua-parser-js` (8M+ weekly downloads)

## 🔴 What Happened?
The npm account of the `ua-parser-js` package owner was compromised.
- Malicious versions (0.7.29, 0.8.0, 1.0.0) were published
- The malware was designed for crypto mining + credential theft
- 8 million/week downloads → infected thousands of systems within hours
- npm removed the malicious versions within 2 hours

## 🧠 Root Cause
1. **npm account without 2FA**: The attacker stealing (or brute-forcing) an API token was sufficient
2. **Weak monitoring**: Publishing malicious packages on PyPI/npm was not being detected
3. **Automatic updates**: Those depending on ranges like `^0.7.28` were automatically updated

## 💥 Impact
- XMRig Monero cryptominer dropped on Linux/Windows (difficult to detect)
- Discord tokens, browser credentials were stolen
- npm accelerated the process of making 2FA mandatory
- Decision to make "2FA mandatory for npm maintainers" was passed (2022)

## 🎓 Lessons Learned
- **Use lock files** — pin exact versions instead of ranges
- **Use 2FA** — especially mandatory for popular package owners
- **Scan with npm audit / Snyk** — make it mandatory in CI
- **Package signature verify** — npm has offered signature support since 2022

## Vibe Coding Connection
When generating JS code with AI:
- AI recommends popular packages like "ua-parser-js"
- Add "check the npm audit status of the package" to the prompt
- Verify hashes in the lock file

## 🔗 References
- https://www.helpnetsecurity.com/2021/10/26/ua-parser-js-compromised/ (ua-parser-js compromised — cryptominers delivered)
- https://www.bleepingcomputer.com/news/security/popular-npm-library-hijacked-to-install-password-stealers-miners/
