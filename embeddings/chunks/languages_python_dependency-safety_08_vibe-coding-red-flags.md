---
source: "languages/python/dependency-safety.md"
title: "Dependency Safety — Python Supply Chain"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe Coding Red Flags

In AI-generated Python projects, flag these immediately:

```dockerfile
# requirements.txt without version pins
flask
requests
numpy

# Inline pip install in production code
subprocess.run(["pip", "install", package_name])

# Typo-squatted imports
import requeests
import beautfulsoup4
import panda
import django

# No dependency lock file
# (Missing: requirements.txt with versions, Pipfile.lock, poetry.lock)
```

> **Golden Rule:** AI-generated `requirements.txt` files are the most common supply chain vulnerability. Always pin exact versions and verify hashes before deployment.