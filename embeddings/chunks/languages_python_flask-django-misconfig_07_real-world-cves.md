---
source: "languages/python/flask-django-misconfig.md"
title: "Flask & Django Misconfigurations"
heading: "Real-World CVEs"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs

| CVE | Description | CVSS | Impact |
|---|---|---|---|
| **CVE-2023-30861** | Flask caches a response with `Set-Cookie` when the `session` is refreshed but not accessed, so `Vary: Cookie` is omitted — a caching proxy can then serve one client's `session` cookie to other clients (fixed 2.2.5 / 2.3.2) | 7.5 | Session cookie disclosure / hijack |
| **CVE-2024-6221** | flask-cors 4.0.1 sets `Access-Control-Allow-Private-Network: true` by default, exposing private-network resources to cross-origin requests (fixed 5.0.0) | 7.5 | CORS / private-network data exposure |
| **CVE-2019-19844** | Django password-reset account takeover — an email that is equal to a victim's after Unicode case-folding gets the victim's reset token (fixed 1.11.27 / 2.2.9 / 3.0.1) | 9.8 | Account takeover |
| **CVE-2022-36359** | Django Reflected File Download — the `Content-Disposition` filename of a `FileResponse` derived from user input (fixed 3.2.15 / 4.0.7) | 8.8 | Reflected file download |
| **CVE-2023-31047** | Django `forms.FileField` / `ImageField` validation bypassed when one form field uploads multiple files (fixed 3.2.19 / 4.1.9 / 4.2.1) | 9.8 | Upload validation bypass |

---