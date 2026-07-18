---
source: "languages/python/supply-chain-deep.md"
title: "PyPI Supply Chain Security: Deep Dive"
heading: "Defense-in-Depth Strategy"
category: "language-vuln"
language: "python"
severity: "high"
tags: [attack, language-vuln, overview, python, vector]
chunk: 9/10
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