---
source: "languages/python/command-injection.md"
title: "Command Injection — Python"
heading: "Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] NEVER use `shell=True` in `subprocess` calls with user input
- [ ] NEVER use `os.system()` with any external input
- [ ] ALWAYS pass command arguments as a **list**, not a string
- [ ] Use `subprocess.run()` with `shell=False` (default) — never omit this
- [ ] Validate/normalize all user input before any command execution
- [ ] Prefer Python libraries over shell commands (e.g., `shutil` over `cp`, `paramiko` over `ssh`)
- [ ] Set `timeout` on all subprocess calls to prevent DoS
- [ ] Use `shlex.split()` to parse command strings into lists (NOT security — only parsing)
- [ ] Run commands with least privilege (avoid root/sudo in subprocess)
- [ ] Restrict allowed commands via a whitelist when command execution is required
- [ ] Use containerization/sandboxing for any code that executes commands

---