---
source: "languages/python/dependency-safety.md"
title: "Dependency Safety — Python Supply Chain"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 4/8
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