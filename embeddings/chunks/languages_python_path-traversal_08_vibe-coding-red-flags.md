---
source: "languages/python/path-traversal.md"
title: "Path Traversal — Python"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe Coding Red Flags

In AI-generated Python, flag these immediately:

```python
open(request.args.get('path'))                    # 💥 Direct user-controlled
open(f'/dir/{user_input}')                        # 💥 Concatenation
os.path.join('/dir/', user_input)                 # ⚠️ Bypassable with absolute path
Path('/dir/') / user_input                        # ⚠️ Same bypass
send_file(os.path.join('/dir/', user_input))      # ⚠️ Traversal risk
zipfile.extractall('/dir/')                       # ⚠️ Zip slip without validation
```

> **Golden Rule:** `os.path.join()` is NOT a security function. It's a string concatenation utility. Always call `os.path.realpath()` and check the prefix.