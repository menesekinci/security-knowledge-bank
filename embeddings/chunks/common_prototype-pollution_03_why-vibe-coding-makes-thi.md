---
source: "common/prototype-pollution.md"
title: "Prototype Pollution"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, fixed, prevention, vibe, vulnerable, what]
chunk: 3/8
---

## Why Vibe Coding Makes This Worse

- **AI uses merge/clone operations:** `Object.assign()`, spread `{...obj}`, `_.merge()`, `$.extend()` are common AI patterns
- **AI doesn't validate `__proto__`:** Generated merge functions don't check for `__proto__`, `constructor.prototype`
- **AI uses unsafe npm packages:** Many merge libraries had prototype pollution vulnerabilities
- **AI-generated deep clone:** AI writes recursive clone without prototype pollution protection
- **AI generates config merging:** Deep merging user config with default config is a common AI pattern