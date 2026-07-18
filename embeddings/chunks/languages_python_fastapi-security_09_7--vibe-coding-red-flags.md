---
source: "languages/python/fastapi-security.md"
title: "FastAPI Security Deep Dive"
heading: "7. Vibe-Coding Red Flags (FastAPI-Specific)"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, explanation, language-vuln, overview, python, secure, vulnerability, vulnerable]
chunk: 9/10
---

## 7. Vibe-Coding Red Flags (FastAPI-Specific)

1. **`debug=True` in `FastAPI()`** — Always an accidental production deployment waiting to happen. AI templates default to this.
2. **`app = FastAPI()` with no auth middleware** — Every endpoint is public by default. AI rarely adds auth unless prompted.
3. **`allow_origins=["*"]`** — The single most common AI-generated CORS configuration. Combined with a public API, this invites cross-origin abuse.
4. **No `docs_url=None`** — AI leaves Swagger/ReDoc open in every generated scaffold. Attackers get a full API inventory for free.
5. **`file.filename` used directly in path operations** — Path traversal vulnerability 101. AI doesn't sanitize filenames.
6. **F-string SQL queries** — AI models trained on tutorials generate `f"SELECT * FROM {table} WHERE id = {id}"` constantly.
7. **Hardcoded JWT secret** — AI writes `SECRET_KEY = "my-secret"` in the source file, checked into git, visible to everyone.
8. **No file size limit on `UploadFile`** — AI doesn't add size validation, allowing DoS via large uploads.
9. **`CORSMiddleware` added but no auth** — Common AI pattern: "adds CORS to fix frontend errors" but doesn't add authentication.
10. **No `try/except` on `db_session`** — AI generators frequently omit error handling, leaking stack traces with database connection details.
11. **`SessionMiddleware(secret_key="hardcoded")`** — Hardcoded Starlette session key enables session forgery.
12. **No rate limiter on `/login` or `/register`** — AI generates auth endpoints but never adds brute-force protection.
13. **`allow_credentials=True` with `allow_origins=["*"]`** — An invalid but not rejected CORS configuration that makes CSRF trivial.
14. **Using `raise` without HTTPException** — AI generates bare `raise Exception()` which FastAPI catches as 500 Internal Server Error, potentially leaking information.

---