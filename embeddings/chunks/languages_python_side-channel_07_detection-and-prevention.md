---
source: "languages/python/side-channel.md"
title: "Side-Channel Risks in Python"
heading: "Detection and Prevention"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [additional, cve-2021-23336, cve-2023-50782, cve-2024-23342, language-vuln, overview, python, python-cryptography, python-ecdsa]
chunk: 7/8
---

## Detection and Prevention

### Tools

- **Timing attack detection:** `timing_attack` package for Python
- **Error message auditing:** Custom Semgrep rules for `traceback.format_exc()` in endpoints
- **Static analysis:** Bandit rule `B106` for hardcoded passwords, custom rules for error verbosity

### Secure Coding Checklist

| Pattern | Vulnerable | Secure |
|---------|-----------|--------|
| Error responses | Different for each failure type | Uniform generic errors |
| Password check | `User not found` vs `Wrong password` | Always `Invalid credentials` |
| API enumeration | `404` vs `403` vs `200` | Same response for unauthorized |
| Stack traces | Exposed in production | Logged internally only |
| Exception types | Different types for different failures | Single sanitized exception |
| Timing | Short-circuit comparisons | Constant-time operations |

---