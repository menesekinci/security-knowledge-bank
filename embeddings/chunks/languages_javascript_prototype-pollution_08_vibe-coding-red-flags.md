---
source: "languages/javascript/prototype-pollution.md"
title: "Prototype Pollution — JavaScript"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe Coding Red Flags

In AI-generated JavaScript, flag these immediately:

```javascript
function merge(target, source) { ... }       // 💥 Custom merge without safety
function deepMerge(target, source) { ... }   // 💥 Custom deep merge
function extend(target, source) { ... }      // 💥 jQuery-style extend
Object.assign(target, source)                // ⚠️ If source has __proto__
{ ...defaults, ...userInput }                // ⚠️ If userInput has __proto__
_.merge(target, source)                      // ⚠️ Check lodash version
_.defaultsDeep(target, source)               // ⚠️ Check lodash version
```

> **Golden Rule:** Any function that recursively copies properties from user input onto an object is a prototype pollution vulnerability until proven otherwise. Use libraries specifically designed for safe merging, never custom implementations.