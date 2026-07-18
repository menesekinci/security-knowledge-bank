---
source: "languages/python/supply-chain-deep.md"
title: "PyPI Supply Chain Security: Deep Dive"
heading: "Attack Vector 3: Package Hijacking (Account Takeover)"
category: "language-vuln"
language: "python"
severity: "high"
tags: [attack, language-vuln, overview, python, vector]
chunk: 5/10
---

## Attack Vector 3: Package Hijacking (Account Takeover)

### LiteLLM Compromise (2025)

**Source:** https://www.facebook.com/CQURE/posts/litellm-has-confirmed-a-supply-chain-compromise-involving-malicious-pypi-package/1371313088364143/

In 2025, LiteLLM (a popular AI proxy) confirmed a supply chain compromise. A maintainer's PyPI account credentials were stolen (likely via phishing or session hijacking), allowing attackers to upload malicious versions (v1.82.7 and v1.82.8).

### The Attack Chain

```
1. Maintainer's PyPI account compromised
2. Attacker uploads v1.82.7 with backdoor
3. pip install liteLLM downloads compromised version
4. Backdoor activates, exfiltrates API keys and model configuration
```

### Prevention: 2FA and API Tokens

```bash
# PyPI now requires 2FA for all maintainers (as of 2024)

# Use limited-scope API tokens, not passwords
# PyPI tokens can be scoped to:
# - A specific project
# - Upload only (no delete)
# - Expire after a set time
```

---