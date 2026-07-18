---
source: "languages/python/index.md"
title: "Python Security — Overview"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [critical, cves, file, index, language-vuln, python, vibe]
---

# Python Security — Overview

> **Audience:** Developers using AI-assisted coding (Claude, ChatGPT, Cursor, Copilot) who need to understand Python-specific security pitfalls.
> **Target:** Vibe Coding security knowledge base — practical, actionable, CVE-backed.

---

## The Python Security Landscape

Python is the most popular language for AI-assisted coding. Its readability, vast ecosystem, and dynamic nature make it a magnet for Vibe Coding — but those same qualities create recurring security traps. AI models are statistically likely to generate unsafe patterns because those patterns dominate training data (especially forum code, tutorials, and Stack Overflow answers).

### Why Python Is Particularly Vulnerable in AI-Generated Code

1. **Dynamic execution is idiomatic.** `eval()`, `exec()`, `getattr()`, `__import__()` are common patterns. AI models see these used casually in training data and reproduce them without guardrails.
2. **Pickle is everywhere in ML/AI.** The data science and ML ecosystem (PyTorch, scikit-learn, pandas) uses pickle for model serialization. AI coding assistants naturally reach for pickle without considering alternatives.
3. **Framework defaults are production-hostile.** Django's `DEBUG=True`, Flask's development server, and SQLAlchemy's raw text execution all appear in tutorials. AI models trained on tutorials replicate these defaults.
4. **Supply chain is complex.** `pip install` with no pinning, typo-squatting packages (e.g., `requeests` vs `requests`), and malicious packages in PyPI (over 250,000+ packages with minimal vetting).
5. **Template engines are powerful.** Jinja2, Mako, and Django Templates offer server-side execution capabilities that AI models use freely.

### Top Python Security Findings in AI-Generated Code

| Vulnerability | Frequency in AI Code | Severity |
|---|---|---|
| `eval()` / `exec()` injection | Very High | Critical |
| Pickle deserialization | High | Critical |
| SQL injection via raw queries | High | Critical |
| Command injection (`shell=True`) | High | Critical |
| SSTI in Jinja2 | Medium | Critical |
| Insecure dependencies (no pinning) | Very High | High |
| Hardcoded secrets / DEBUG mode | Very High | High |
| Path traversal | Medium | High |
| Weak cryptography | Medium | High |

### The Vibe Coding Factor

AI code generators excel at producing *functional* code but struggle with *defensive* code. Common failure modes:

- **Missing input validation** — AI assumes inputs are well-formed
- **No principle of least privilege** — AI uses the most powerful function available (e.g., `eval` instead of `ast.literal_eval`)
- **Incorrect error handling** — AI swallows or over-exposes error details
- **Outdated library usage** — AI training data lags behind security patches

> **Key Insight:** AI models are *interpolative*, not *reasoning* about security. They generate what they've seen most often — and what's seen most often in Python is tutorial code, not hardened production code.

---

## Critical CVEs Relevant to Python AI-Generated Code

| CVE | Description | Relevance |
|---|---|---|
| CVE-2025-1716 | Picklescan analysis bypass leading to RCE via pickle deserialization | ML pipeline attacks |
| CVE-2025-3108 | Deserialization RCE in llama_index JsonPickleSerializer | AI framework supply chain |
| CVE-2025-23211 | Jinja2 SSTI to RCE in Tandoor Recipes | Template injection in web apps |
| CVE-2024-6982 | RCE via `eval()` in parisneo/lollms | AI chat platform eval injection |
| CVE-2024-46946 | RCE in Langchain-experimental via code injection | LLM framework vulnerability |
| CVE-2024-45848 | Eval injection in MindsDB ChromaDB integration | AI database platform |
| CVE-2024-45595 | Eval injection in D-Tale chart filter | Data science tooling |

---

## The Vibe Coding Security Checklist

Before deploying AI-generated Python code, verify:

- [ ] No `eval()`, `exec()`, or `compile()` with user-controllable input
- [ ] `pickle.load()` is never called on untrusted data (use `safetensors` or JSON instead)
- [ ] All SQL queries use parameterized statements (ORMs with proper API usage)
- [ ] `subprocess.call()` / `os.system()` never uses `shell=True` with user input
- [ ] File paths are normalized and validated against a whitelist
- [ ] `requirements.txt` / `pyproject.toml` pins exact versions
- [ ] Flask `DEBUG=False`, Django `DEBUG=False` in production
- [ ] `SECRET_KEY`, `API_KEY` are environment variables, not hardcoded
- [ ] `random` module is never used for security purposes (use `secrets`)
- [ ] Template auto-escaping is enabled (Jinja2, Django)
- [ ] `cors` is configured with specific origins, not `*`

---

## File Index

| File | Topic |
|---|---|
| `pickle-rce.md` | Pickle deserialization RCE |
| `eval-exec.md` | eval(), exec(), compile() dangers |
| `template-injection.md` | Jinja2 SSTI, Mako, Django template injection |
| `sql-injection.md` | Raw SQL, ORM misuses (SQLAlchemy raw text) |
| `command-injection.md` | os.system(), subprocess shell=True, shlex pitfalls |
| `path-traversal.md` | open(), PathLib, os.path issues |
| `dependency-safety.md` | pip supply chain, typo-squatting, requirements pinning |
| `crypto-mistakes.md` | cryptography library misuse, hashlib, random vs secrets |
| `flask-django-misconfig.md` | DEBUG=True, SECRET_KEY hardcode, CORS |

---

*Last updated: July 2026 — CVEs and patterns reflect current threat landscape.*
