---
source: "languages/javascript/eval-injection.md"
title: "Eval Injection — JavaScript"
heading: "Prevention Checklist"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] NEVER use `eval()` — there is always a safer alternative
- [ ] NEVER use `new Function()` with user input
- [ ] NEVER use `setTimeout()` or `setInterval()` with string arguments (Node.js emits a warning)
- [ ] Use `JSON.parse()` instead of `eval()` for JSON parsing
- [ ] Use object lookups or Maps instead of dynamic code execution
- [ ] For template rendering, use a proper template engine (Handlebars, EJS, Pug)
- [ ] For mathematical expressions, use `mathjs` or a dedicated expression parser
- [ ] For Node.js sandboxed execution, use `vm2` (note: vm2 has known escapes — prefer containers)
- [ ] Set `NODE_OPTIONS=--disallow-code-generation-from-strings` in Node.js
- [ ] Use ESLint rule `no-eval` and `no-implied-eval` to catch these patterns

---