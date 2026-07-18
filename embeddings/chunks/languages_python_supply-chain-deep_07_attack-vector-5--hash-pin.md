---
source: "languages/python/supply-chain-deep.md"
title: "PyPI Supply Chain Security: Deep Dive"
heading: "Attack Vector 5: Hash Pinning Failures"
category: "language-vuln"
language: "python"
severity: "high"
tags: [attack, language-vuln, overview, python, vector]
chunk: 7/10
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