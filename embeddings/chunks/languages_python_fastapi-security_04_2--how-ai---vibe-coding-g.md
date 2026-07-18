---
source: "languages/python/fastapi-security.md"
title: "FastAPI Security Deep Dive"
heading: "2. How AI / Vibe Coding Generates These Vulnerabilities"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, explanation, language-vuln, overview, python, secure, vulnerability, vulnerable]
chunk: 4/10
---

## 2. How AI / Vibe Coding Generates These Vulnerabilities

| Prompt | Generated Pattern | Vulnerability |
|--------|-------------------|---------------|
| "Build a REST API with FastAPI" | `app = FastAPI(debug=True)`, no auth, `CORSMiddleware(allow_origins=["*"])` | Debug mode in production, CORS wide open, no auth |
| "Add user authentication" | Hardcoded JWT secret, no refresh token rotation, no rate limiting on `/login` | JWT forgery, brute-force login |
| "File upload endpoint" | `UploadFile` with no size limit, no type check, original filename used | Path traversal, DoS, malware upload |
| "Database query endpoint" | Raw SQL with f-strings instead of ORM | SQL injection |
| "Admin dashboard" | No middleware, all endpoints public, Swagger enabled | Full API exposure |
| "Add CORS for frontend" | `allow_origins=["*"]`, `allow_credentials=True` | CSRF bypass when credentials allowed with wildcard |
| "Rate limiting" | Not generated at all | No rate limiting on any endpoint |

---