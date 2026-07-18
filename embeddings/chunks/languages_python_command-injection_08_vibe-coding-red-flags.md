---
source: "languages/python/command-injection.md"
title: "Command Injection — Python"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe Coding Red Flags

In AI-generated Python, flag these immediately:

```python
os.system(f"...{user_input}...")        # 💥 Classic
subprocess.run(f"...{user_input}...", shell=True)  # 💥 Shell=True
subprocess.Popen(f"...{user_input}...", shell=True)  # 💥 Shell=True
os.popen(f"...{user_input}...")          # 💥 Deprecated, still dangerous
commands.getoutput(f"...{user_input}...") # 💥 Python 2, but still seen
check_output(f"...{user_input}...", shell=True)  # 💥 check_output shell
```

> **Golden Rule:** If `shell=True` appears in any subprocess call with even a hint of external input, it's a critical vulnerability. Replace with list-based arguments immediately.