---
source: "languages/python/path-traversal.md"
title: "Path Traversal — Python"
heading: "Real-World CVEs"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2007-4559** | Python `tarfile` — `extract()`/`extractall()` follow `..` sequences in TAR member names ("tarbomb") | Arbitrary file overwrite → potential RCE |
| **CVE-2024-23334** | aiohttp 1.0.5–3.9.1 — `web.static(..., follow_symlinks=True)` fails to canonicalize paths, allowing `../` traversal | Arbitrary file read |
| **CVE-2023-41105** | CPython 3.11–3.11.4 — `os.path.normpath()` truncates the path at an embedded `\0` byte, bypassing allowlist checks | Path-allowlist bypass |
| **CVE-2021-33203** | Django <2.2.24 / <3.1.12 / <3.2.4 — `admindocs` `TemplateDetailView` directory traversal outside template roots | Arbitrary file existence/content disclosure |
| **CVE-2019-14322** | Werkzeug <0.15.5 — `SharedDataMiddleware` mishandles Windows drive letters (e.g. `C:`) via `os.path.join()` | Arbitrary file read (Windows) |

---