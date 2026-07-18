---
source: "languages/python/dependency-safety.md"
title: "Dependency Safety — Python Supply Chain"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 3/8
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