---
source: "languages/python/eval-exec.md"
title: "eval(), exec(), compile() Dangers"
heading: "Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, cves, explanation, language-vuln, prevention, python, real-world, secure, vulnerability]
chunk: 5/7
---

## Prevention Checklist

- [ ] Never pass user input to `eval()`, `exec()`, or `compile()`
- [ ] Use `ast.literal_eval()` for parsing Python literal values from input
- [ ] Use dedicated math expression libraries (`numexpr`, `simpleeval`) for calculations
- [ ] Use structured data formats (JSON, YAML with schema validation) instead of dynamic config
- [ ] If dynamic code execution is required, sandbox in a container or VM
- [ ] Audit all AI-generated code for `eval(`, `exec(`, `compile(` patterns
- [ ] Use static analysis tools (bandit, semgrep) to detect eval/exec usage
- [ ] Configure CI/CD to fail builds containing eval/exec on user-controlled data
- [ ] Prefer `getattr()` for dynamic attribute access instead of eval
- [ ] Prefer `importlib.import_module()` for dynamic imports instead of `__import__()` via eval

---