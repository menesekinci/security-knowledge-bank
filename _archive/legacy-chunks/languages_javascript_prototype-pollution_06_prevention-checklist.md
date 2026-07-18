---
source: "languages/javascript/prototype-pollution.md"
title: "Prototype Pollution — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 6
total_chunks: 8
heading: "Prevention Checklist"
---

## Prevention Checklist

- [ ] NEVER write recursive merge functions without `__proto__` / `constructor.prototype` checks
- [ ] Use `Object.create(null)` for dictionaries/maps that accept user keys
- [ ] Use safe merge libraries: `lodash@>=4.17.5`, `deepmerge`, `just-safe-set`
- [ ] Validate JSON inputs against a strict schema before processing
- [ ] Freeze `Object.prototype` in security-critical Node.js apps
- [ ] Use `Map` objects instead of plain objects for dynamic key storage
- [ ] Sanitize query string parsers to reject `__proto__` keys
- [ ] In Express, use `express.json()` with `bodyParser.json({ strict: true })`
- [ ] Apply `Object.freeze(Object.prototype)` in production initialization
- [ ] Audit all AI-generated code for `merge`, `assign`, `spread`, and `__proto__` usage

---