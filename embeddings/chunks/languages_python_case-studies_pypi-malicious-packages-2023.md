---
source: "languages/python/case-studies/pypi-malicious-packages-2023.md"
title: "PyPI Malicious Package (2023) — Python Supply Chain"
category: "case-study"
language: "python"
severity: "critical"
tags: [case-study, cause, happened, impact, python, root, system, target, what, when]
---

# PyPI Malicious Package (2023) — Python Supply Chain

## 📅 When Did It Happen?
2023 (ongoing)

## 🎯 Target System
Python Package Index (PyPI) — Python developers

## 🔴 What Happened?
A researcher (**Bar Lanyado of Lasso Security**, early 2024) showed that AI assistants repeatedly hallucinate a non-existent Python package, `huggingface-cli`, instead of the real `huggingface_hub[cli]`.
- He uploaded an **empty** package under that hallucinated name to PyPI as a proof of concept.
- It received **30,000+ authentic downloads** in three months — Alibaba even copy-pasted the hallucinated install command into a public repo's README.
- This "slopsquatting" (aka hallucination squatting) confirmed AI-suggested-but-fake package names as a real supply-chain attack surface.

More serious real-world cases in the same category:
- **ctx** (May 2022): the maintainer's expired email domain was re-registered by an attacker who took over the PyPI account and pushed malicious releases that exfiltrated `os.environ` — including `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` — to a Heroku endpoint. ~27,000 malicious downloads over May 14–24, 2022.
- **python3-dateutil** (2019): typosquat of `python-dateutil` — contained malware (it imported the also-malicious `jeIlyfish`).
- **jeIlyfish** (discovered Dec 2019): typosquat of `jellyfish` (capital "I" mistaken for lowercase "l") that stole SSH/GPG keys.

## 🧠 Root Cause
1. **AI hallucination**: ChatGPT/Claude suggests package names that don't exist
2. **Typo-squatting**: Names with similar spelling to popular packages (published via throwaway accounts)
3. **Dependency confusion**: Publishing a PyPI package with the same name as an internal package
4. **pip install --user**: User-level installation does not prevent system-wide propagation

## 💥 Impact
- AI hallucination discovered as a supply chain attack vector
- PyPI security measures increased (2FA mandatory, project name verification)
- Developers now question packages suggested by AI

## 🎓 Lessons Learned
- **Don't immediately pip install a package suggested by AI** — search PyPI first
- **Before pip install** verify with `pip show <package>`
- **Use hash pinning in requirements.txt** (`pip freeze --hash`)
- **Check the last update date** on PyPI's official site
- **Check signatures on less popular packages**

## Vibe Coding Connection
- Research every package AI suggests on PyPI
- Add to your prompt: "Only suggest packages with 100k+ monthly downloads"
- If ChatGPT suggests a package you've never heard of, tell it "verify this"

## 🔗 Source
- https://www.lasso.security/blog/ai-package-hallucinations (Lasso Security — huggingface-cli)
- https://python-security.readthedocs.io/pypi-vuln/index-2022-05-24-ctx-domain-takeover.html (ctx account takeover)
- https://blog.phylum.io/ai-written-code-can-be-weaponized/
- https://arxiv.org/abs/2305.13872
