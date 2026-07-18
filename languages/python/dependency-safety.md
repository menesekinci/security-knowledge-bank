# Dependency Safety — Python Supply Chain

> **Severity:** High
> **CVSS:** 8.1–9.8 (depending on exploit)
> **AI Generation Risk:** Very High — AI-generated dependency files almost never pin versions or verify package integrity

---

## Vulnerability Explanation

Python's package ecosystem (PyPI) is the largest package registry in the world with over 500,000 packages. Its minimal vetting process makes it a prime target for supply chain attacks. When AI generates Python projects, it produces `requirements.txt` or `pyproject.toml` files with **no version pinning**, **no hash verification**, and often with **typo-squatted package names**.

### Attack Vectors Specific to AI-Generated Code

1. **No version pinning:** `requests` vs `requests==2.31.0` — unpinned packages auto-update to compromised versions
2. **Typo-squatting:** AI may generate `requeests` or `request` instead of `requests`
3. **Dependency confusion:** AI generates internal-sounding package names that could be registered publicly
4. **Malicious packages in AI training data:** Packages like `colourama` (typo-squatting `colorama`) appear in training data
5. **Transitive dependency attacks:** AI doesn't audit sub-dependencies

---

## How AI / Vibe Coding Generates This

### 1. Unpinned Requirements

```dockerfile
# 🚫 VULNERABLE — AI-generated Dockerfile
FROM python:3.11

COPY requirements.txt .
RUN pip install -r requirements.txt  # 💥 No version pins = time bomb

# requirements.txt:
flask
requests
numpy
pandas
# If flask gets compromised tomorrow, this builds with malware
```

### 2. Typo-Squatted Packages

```python
# 🚫 VULNERABLE — AI-generated import with typo
import requeests  # 💥 Not 'requests' — possible malicious package
import beautfulsoup4  # 💥 Not 'beautifulsoup4'
import cryptograph  # 💥 Not 'cryptography'
```

### 3. Dependency Confusion in AI-Generated Configs

```python
# 🚫 VULNERABLE — AI-generated pyproject.toml
[tool.poetry.dependencies]
python = "^3.11"
flask = "^2.3.0"
# If the project uses "my-internal-lib", an attacker registers it on PyPI
my-internal-lib = "^1.0.0"  # 💥 Public PyPI has this name now!
```

### 4. No Hash Verification

```dockerfile
# 🚫 VULNERABLE — pip install without hash check
RUN pip install -r requirements.txt
# No --require-hashes flag — any version can be swapped
```

### 5. Pre-release / Nightly Builds

```python
# 🚫 VULNERABLE — AI using experimental builds
[tool.poetry.dependencies]
pandas = {version = "*", source = "pypi"}  # 💥 Gets latest (possibly malicious) version
```

### 6. AI Installing Packages Inline

```python
# 🚫 VULNERABLE — AI-generated inline install
import subprocess

# AI installs packages at runtime in the middle of code
subprocess.run([sys.executable, "-m", "pip", "install", package_name])  # 💥
```

### Why AI Does This

- **Tutorials don't pin versions:** Most Python tutorials show `pip install flask`, not `pip install flask==2.3.0`
- **AI training data is time-frozen:** The AI learned "latest" versions — it doesn't account for future compromises
- **Typo generation is a language model artifact:** AI statistically predicts tokens; `requeests` is a plausible misspelling
- **No security mental model:** AI doesn't simulate an attacker registering a dependency-confusion package

---

## Vulnerable Code Example

### AI-Generated Project with Supply Chain Vulnerabilities

```python
# 🚫 VULNERABLE — Complete AI-generated project

# requirements.txt (AI-generated — no pins)
flask
pandas
numpy
requests
scikit-learn
torch
transformers
beautifulsoup4

# main.py
from flask import Flask
import pandas as pd
import numpy as np
import requests
from transformers import pipeline

app = Flask(__name__)

@app.route('/analyze')
def analyze():
    text = request.args.get('text')
    classifier = pipeline('sentiment-analysis')
    return {'sentiment': classifier(text)[0]}

# 💥 Issues:
# 1. No version pins — any of the 7 packages could be compromised tomorrow
# 2. transformers pulls 50+ transitive dependencies
# 3. No hash verification
# 4. If flask==2.3.3 gets compromised, this app auto-pulls it
```

### Typosquatting Demo

```python
# What the AI meant to write:
import requests  # ✅ Correct

# What AI actually generates (seen in real code):
import requeests    # 💥 Possible malicious package
import reqests      # 💥 
import request      # 💥 'request' vs 'requests' — different package!
```

### Inline Package Installation in Production

```python
# 🚫 VULNERABLE — AI-generated plugin system
import subprocess
import sys

def install_plugin(plugin_name):
    # AI installs packages at runtime
    subprocess.run([
        sys.executable, "-m", "pip", "install",
        plugin_name  # 💥 Attacker sends "evil-pkg; curl ..."
    ], check=True)
```

---

## Secure Code Fix

### Fix 1: Pin Exact Versions

```properties
# ✅ SAFE — Pinned requirements.txt
flask==3.0.0
pandas==2.1.4
numpy==1.26.2
requests==2.31.0
scikit-learn==1.3.2
torch==2.1.2
transformers==4.36.2
beautifulsoup4==4.12.2
```

### Fix 2: Use Hash Verification

```dockerfile
# ✅ SAFE — Install with hash verification
COPY requirements.txt .
RUN pip install --require-hashes -r requirements.txt

# requirements.txt with hashes:
# (Generated by: pip freeze --require-hashes > requirements.txt)
flask==3.0.0 --hash=sha256:abc123...
pandas==2.1.4 --hash=sha256:def456...
```

### Fix 3: Use Hashin for Automatic Hash Generation

```bash
# ✅ SAFE — Use hashin to generate hashes
pip install hashin
hashin flask==3.0.0 pandas==2.1.4
# Automatically generates hashes for all platforms
```

### Fix 4: Dependency Scanning in CI

```yaml
# ✅ SAFE — GitHub Actions dependency scanning
name: Dependency Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install pip-audit safety
      - name: Audit dependencies
        run: |
          pip-audit
          safety check -r requirements.txt
      - name: Scan for typosquatting
        run: |
          pip install pip-check
          pip check
```

### Fix 5: Use pip-audit for CVE Scanning

```bash
# ✅ SAFE — Scan for known vulnerabilities
pip install pip-audit
pip-audit -r requirements.txt
# Reports CVEs in each package
```

### Fix 6: Prevent Dependency Confusion

```python
# ✅ SAFE — Use a private index with fallback restrictions
# pip install --index-url https://private.company.com/simple/ --extra-index-url https://pypi.org/simple/
# Or use pip's trusted-host configuration

# For Poetry:
[tool.poetry.source]
name = "private"
url = "https://private.company.com/simple/"
default = true  # Only look at private index first
secondary = true
```

### Fix 7: Use pip freeze for Lock Files

```bash
# ✅ SAFE — Generate deterministic builds
pip install -r requirements.in  # Unpinned "source" requirements
pip freeze > requirements.txt   # Pinned "lock" file
```

---

## Prevention Checklist

- [ ] PIN every dependency to an exact version (`==`) — no ranges (`>=`, `~=`, `*`)
- [ ] VerifY hash integrity with `--require-hashes` or `hashin`
- [ ] Run `pip-audit` or `safety` in CI to detect known CVEs
- [ ] Use `pip freeze` or `pip-compile` (pip-tools) for deterministic builds
- [ ] Never install packages at runtime in production
- [ ] Review AI-generated package names for typos (e.g., `requeests` vs `requests`)
- [ ] Use private package indexes for internal packages with fallback controls
- [ ] Scan transitive dependencies (use `pipdeptree` to visualize)
- [ ] Enable Dependabot/Renovate for automatic security updates with review
- [ ] Use `pip install --no-deps` and install dependencies explicitly
- [ ] Set `PIP_REQUIRE_VIRTUALENV=true` to prevent system-wide installs
- [ ] Monitor PyPI for typo-squatted versions of your popular packages

---

## Real-World Supply Chain Attacks

| Attack | Year | Method | Impact |
|---|---|---|---|
| **PyTorch Dependency Confusion** | 2022 | Attacker registered `pytorch` on PyPI (different from `torch`) | Code execution in CI |
| **ctx / phpass** | 2023 | Malicious packages on PyPI stealing AWS keys | Credential theft |
| **Colourama** | 2023 | Typo-squatting `colorama` | Malware distribution |
| **Requests Typosquatting** | 2023 | Packages like `requestts`, `reqests` | Credential theft |
| **PyPI Malicious Package Flood** | 2024 | 200+ packages with dependency confusion names | Supply chain compromise |
| **September 2025 npm** | 2025 | 200+ packages compromised via maintainer account takeover | Similar patterns apply to PyPI |
| **2026 npm Dependency Confusion** | 2026 | 33 malicious npm packages profiling dev environments | Reconnaissance |

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
