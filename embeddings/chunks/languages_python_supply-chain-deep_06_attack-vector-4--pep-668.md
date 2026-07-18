---
source: "languages/python/supply-chain-deep.md"
title: "PyPI Supply Chain Security: Deep Dive"
heading: "Attack Vector 4: PEP 668 and Environment Isolation"
category: "language-vuln"
language: "python"
severity: "high"
tags: [attack, language-vuln, overview, python, vector]
chunk: 6/10
---

## Attack Vector 4: PEP 668 and Environment Isolation

**Source:** https://peps.python.org/pep-0668/

PEP 668 (adopted in Python 3.11+) introduces externally-managed environment markers to prevent pip from conflicting with system package managers.

### Security Implication

While PEP 668 is designed to prevent accidental breakage, it also makes it harder to detect supply chain attacks because:

- `pip install` on system Python now fails with an error
- Developers use `--break-system-packages` to bypass (which also bypasses safety checks)
- Virtual environments become mandatory — but not everyone uses them

```bash
# PEP 668 error on Debian/Ubuntu with Python 3.11+
$ pip install requests
error: externally-managed-environment
× This environment is externally managed
╰─> To install Python packages system-wide, try apt install python3-requests

# Dangerous bypass:
pip install malicious-package --break-system-packages  # Skips all safety checks
```

### Best Practice

```bash
# Always use virtual environments — don't bypass PEP 668
python -m venv .venv
source .venv/bin/activate
pip install malicious-package  # This would still install it, but at least
# not system-wide. Validate packages before installing.
```

---