---
source: "languages/python/pickle-rce.md"
title: "Pickle Deserialization RCE"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, cves, explanation, language-vuln, python, real-world, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe Coding Red Flags

When reviewing AI-generated Python, flag these immediately:

```python
pickle.load(...)              # Always suspicious
pickle.loads(...)             # Always suspicious
joblib.load(...)              # Uses pickle underneath
torch.load(..., pickle_module=pickle)  # If weights_only=False
dill.load(...)                # More dangerous than pickle
cloudpickle.load(...)         # Even more powerful, equally dangerous
```

> **Remember:** If you see `pickle.load()` in AI-generated code, assume it's a security vulnerability until proven otherwise by a threat model.