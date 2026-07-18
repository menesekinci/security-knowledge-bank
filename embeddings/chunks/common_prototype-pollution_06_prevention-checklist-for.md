---
source: "common/prototype-pollution.md"
title: "Prototype Pollution"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, fixed, prevention, vibe, vulnerable, what]
chunk: 6/8
---

## Prevention Checklist for AI Prompts

```
✅ PROTOTYPE POLLUTION PREVENTION:
- Use Object.create(null) for dictionaries/maps that accept user input
- Use Map instead of plain objects for key-value storage
- Before merge/clone, check and reject keys named __proto__, constructor, prototype
- Use libraries that are patched against pollution (lodash >= 4.17.21, jQuery >= 3.5.0)
- Use Object.freeze(Object.prototype) in critical environments
- Never deep-merge untrusted user input into existing objects
- Use JSON Schema validation before processing user objects
- Sanitize all incoming JSON with key filtering
- Use immutable patterns (immer, immutable.js)
- Pin npm packages to versions with prototype pollution fixes
```

### NPM Package Security

| Package | Safe Version | Notes |
|---|---|---|
| lodash | >= 4.17.21 | CVE-2020-8203 (prototype pollution in `zipObjectDeep`) |
| jQuery | >= 3.4.0 | CVE-2019-11358 (prototype pollution in `$.extend`) |
| $.extend | >= 3.4.0 | Deep extend polluted `Object.prototype` before 3.4.0 |
| handlebars | >= 4.3.0 | CVE-2019-19919 (prototype pollution) |
| merge | >= 2.1.1 | npm merge package |
| immer | >= 8.0.1 | Doesn't allow prototype stuff |

---