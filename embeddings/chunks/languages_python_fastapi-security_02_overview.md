---
source: "languages/python/fastapi-security.md"
title: "FastAPI Security Deep Dive"
heading: "Overview"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, explanation, language-vuln, overview, python, secure, vulnerability, vulnerable]
chunk: 2/10
---

## Overview

FastAPI is the dominant Python framework for AI-generated APIs. Its automatic OpenAPI/Swagger generation, Pydantic-based validation, and async-first design make it the default choice for LLM-generated backend code. However, **these same features create unique security risks** that are amplified by AI coding assistants:

- **Automatic OpenAPI docs are publicly accessible by default** — exposing every endpoint, schema, and parameter
- **`debug=True` is on by default in AI-generated templates** — leaking stack traces and source code
- **CORS is frequently set to `allow_origins=["*"]`** — opening the API to any website
- **Pydantic type coercion** — AI-generated models may have dangerous type confusion
- **No built-in auth, rate limiting, or CSRF protection** — all must be added manually
- **Starlette underpinnings carry their own CVEs** — FastAPI inherits every Starlette vulnerability

This file documents FastAPI-specific security vulnerabilities, real CVEs across the FastAPI/Starlette/Uvicorn ecosystem, code patterns produced by AI coding assistants (vibe coding), and actionable fixes.

---