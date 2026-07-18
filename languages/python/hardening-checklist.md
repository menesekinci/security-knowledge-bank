# 🐍 Python Security Hardening Checklist

> Items to check in every Python project before deployment.

## ✅ General
- [ ] Is `pip list --outdated` run?
- [ ] Is `pip-audit` or `safety check` done?
- [ ] Are versions pinned in `requirements.txt` / `pyproject.toml`?
- [ ] Is a lock file used? (`poetry.lock`, `pip freeze > requirements.txt`)

## ✅ Code Security
- [ ] Are `eval()`, `exec()`, `compile()` unused?
- [ ] Is `os.system()`, `subprocess shell=True` absent?
- [ ] Is `pickle.load()` not used with untrusted data?
- [ ] Is `yaml.safe_load()` used instead of `yaml.load()`?
- [ ] Are security checks not done with `assert`? (disabled with `python -O`)

## ✅ Web Framework (Django/Flask/FastAPI)
- [ ] Is `DEBUG = False` in production?
- [ ] Is `SECRET_KEY` read from env variable? (no hardcode)
- [ ] Is `ALLOWED_HOSTS` set correctly?
- [ ] Is CORS only open for needed origins?
- [ ] Is rate limiting added?
- [ ] Are session cookies `HttpOnly` + `Secure` + `SameSite`?

## ✅ Database
- [ ] Are all SQL queries parameterized? (ORM or `?` placeholder)
- [ ] Is ORM raw SQL avoided? (or parameterized)
- [ ] Does the database user have minimum privileges?

## ✅ API
- [ ] Is Authentication + Authorization checked on every endpoint?
- [ ] Is input validation present? (pydantic / marshmallow)
- [ ] Is rate limiting present?
- [ ] Are API keys in env variables?

## ✅ Dependency
- [ ] Are unpopular PyPI packages verified?
- [ ] Was the package researched on PyPI before `pip install`?
- [ ] Is hash pinning done?

## 🛡️ Vibe Coding Extra
- [ ] Is every library suggested by AI verified? (hallucination check)
- [ ] Did you test the security code written by AI?
- [ ] Was every eval/exec usage from AI rejected?
