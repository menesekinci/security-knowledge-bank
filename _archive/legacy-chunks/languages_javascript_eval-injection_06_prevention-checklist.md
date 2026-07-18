---
source: "languages/javascript/eval-injection.md"
title: "Eval Injection — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 6
total_chunks: 8
heading: "Prevention Checklist"
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