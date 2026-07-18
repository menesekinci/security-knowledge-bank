---
source: "languages/python/eval-exec.md"
title: "eval(), exec(), compile() Dangers"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, cves, explanation, language-vuln, prevention, python, real-world, secure, vulnerability]
chunk: 7/7
---

## Vibe Coding Red Flags

In AI-generated code, immediately flag:

```python
eval(request...)
eval(user_input...)
eval(data...)
exec(user_code...)
exec(config...)
compile(source, ...)
eval(input(...))
```

> **Golden Rule:** If you see `eval()` in production-facing code, replace it. If you see `eval()` with user input anywhere, treat it as a critical vulnerability requiring immediate fix.