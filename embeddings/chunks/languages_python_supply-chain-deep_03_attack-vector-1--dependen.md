---
source: "languages/python/supply-chain-deep.md"
title: "PyPI Supply Chain Security: Deep Dive"
heading: "Attack Vector 1: Dependency Confusion"
category: "language-vuln"
language: "python"
severity: "high"
tags: [attack, language-vuln, overview, python, vector]
chunk: 3/10
---

## Attack Vector 1: Dependency Confusion

### The Original Attack (2021)

**Source:** https://medium.com/@alex.birsan/dependency-confusion-how-i-hacked-into-apple-microsoft-and-dozens-of-other-companies-4a5d60fec610

In 2021, security researcher Alex Birsan demonstrated a large-scale dependency confusion attack. The core idea: if a company uses a private package name on PyPI (e.g., `internal-auth-lib`), an attacker can upload a public package with the **same name** to PyPI. Since pip prioritizes the highest version number, the attacker's malicious package gets installed.

### How It Works

```bash
# Company uses a private package hosted on their own PyPI server
# Requirements file:
--extra-index-url https://private-pypi.company.com/simple
internal-auth-lib>=1.0.0
common-package==2.3.0

# Attacker uploads "internal-auth-lib" to PUBLIC PyPI with version 9.9.9
# pip downloads the public package because version 9.9.9 > company's 1.0.0
# RCE achieved!
```

### Modern Variant: Conditional Package Names

In 2024-2025, attackers evolved the technique. Instead of guessing internal package names, they:

1. Scrape leaked `requirements.txt` files from GitHub
2. Scan error messages in public bug trackers for unique module names
3. Monitor PyPI uploads to find packages that don't exist yet and squat them

### Detection and Prevention

```bash
# 1. Use pip's --no-deps and explicit dependency pinning
pip install --no-deps -r requirements.txt

# 2. Pin to exact versions with hashes (PEP 665)
# requirements.txt:
internal-auth-lib==1.0.0 --hash=sha256:abc123...

# 3. Use .pypirc to configure index priority
# ~/.pypirc:
[distutils]
index-servers =
    pypi
    private

[private]
repository: https://private-pypi.company.com/simple
username: __token__
password: pypi-xxxx...
priority: always  # pip 23.1+ : always check private first
```

**References:**
- https://medium.com/@alex.birsan/dependency-confusion-how-i-hacked-into-apple-microsoft-and-dozens-of-other-companies-4a5d60fec610

---