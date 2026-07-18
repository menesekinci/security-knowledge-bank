---
source: "languages/python/timing-attacks.md"
title: "Timing Attack Vectors in Python"
heading: "Detection Tools & Prevention"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [cve-2020-25659, cve-2023-50782, cve-2024-23342, general, language-vuln, overview, python, python-cryptography, python-ecdsa, vulnerable]
chunk: 7/8
---

## Detection Tools & Prevention

### Static Analysis

- **Semgrep rule:** `python.lang.security.audit.non-constant-time-comparison`
- **Bandit:** Use `bandit -r .` with custom rules for `==` in security contexts

### Runtime Protection

```python
import hmac
import time
import random

def constant_time_compare(a: str, b: str) -> bool:
    """Drop-in replacement for vulnerable == comparisons."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    # Normalize length
    max_len = max(len(a), len(b))
    a = a.ljust(max_len, '\x00')
    b = b.ljust(max_len, '\x00')
    return hmac.compare_digest(a.encode(), b.encode())
```

### Best Practices

1. **Always use `hmac.compare_digest()`** for comparing secrets, tokens, and HMACs
2. **Upgrade `cryptography` package** regularly (the Bleichenbacher/Marvin timing fix was completed in 42.0.0 — CVE-2023-50782)
3. **Avoid custom crypto implementations** — Python's standard library has constant-time primitives
4. **Add timing jitter** as defense-in-depth for high-security endpoints
5. **Use `secrets.compare_digest()`** (Python 3.8+) as a drop-in for constant-time comparison

---