---
source: "languages/python/case-studies/django-secret-key-hardcoded.md"
title: "Label Studio / Django Hardcoded SECRET_KEY — Python/Django"
category: "case-study"
language: "python"
severity: "critical"
tags: [case-study, cause, happened, impact, python, root, system, target, what, when]
---

# Label Studio / Django Hardcoded SECRET_KEY — Python/Django

## 📅 When Did It Happen?
November 2023 (CVE-2023-43791 / GitHub Security Advisory GHSA-f475-x83m-rx5m; published Nov 8, 2023, patched in Label Studio 1.8.2)

## 🎯 Target System
Label Studio — a popular data labeling platform (developed by HumanSignal). It used the Django web framework.

## 🔴 What Happened?
**Django SECRET_KEY was hardcoded into the source code.** SECRET_KEY is used in Django to sign session tokens, CSRF protection, password reset tokens, and many other things. If SECRET_KEY is leaked:

1. Attacker can forge their own session tokens, impersonating any user
2. CSRF protection can be bypassed
3. Password reset tokens can be forged
4. All signed data becomes insecure

The hardcoded SECRET_KEY was in Label Studio's open source repository, posing a major risk especially in Docker containers or installations running with default configuration.

## 🧠 Root Cause
1. **SECRET_KEY written directly into source code** — this causes every developer and every installation to use the same key
2. **Environment variable not used** — SECRET_KEY should be injectable from outside
3. **Default key in Docker image** — all containers were running with the same key
4. **Secrets in version control (git)** — SECRET_KEY was committed to a public repository

## 💥 Impact
- Session Hijacking
- All signed data becomes insecure
- Access to sensitive labeling data through session theft
- Bypassing CSRF protection
- Full account takeover potential on victim installations

## 🔧 How Was It Fixed?
- GitHub Security Advisory published (GHSA-f475-x83m-rx5m)
- SECRET_KEY removed from source code
- Changed to read from environment variable or `.env` file
- Default key replaced with a randomly generated key
- Migration guide published for users to change their key
- Docker images updated

## 🎓 Lessons Learned
1. **NEVER hardcode secrets in source code** — use environment variables, secret managers, or `.env` files
2. **No default secrets** — Django should throw an error if `SECRET_KEY` is not defined (improved in newer versions)
3. **Secret scanning in Git** — catch secrets before committing with pre-commit hooks
4. **Secret management in Docker images** — don't put secrets in Dockerfile, inject at runtime
5. **Secret rotation** — regularly rotate secrets

## Vibe Coding Connection: How Can This Error Recur in AI Code Generation?
When you ask AI to "create a Django project," it almost always writes `SECRET_KEY = 'hardcoded-key'` in the `settings.py` file. AI is not conscious about secret management and focuses only on producing a "working project." When asking AI to create a Django project, immediately move the SECRET_KEY in the generated code to an environment variable. Also don't forget to change `DEBUG = True` to `False` — AI usually sets it to True as well.

## 🔗 Source / Reference (URL)
- https://github.com/HumanSignal/label-studio/security/advisories/GHSA-f475-x83m-rx5m
- https://www.gitguardian.com/remediation/django-secret-key
