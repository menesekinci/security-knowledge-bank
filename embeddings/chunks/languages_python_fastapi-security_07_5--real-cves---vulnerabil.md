---
source: "languages/python/fastapi-security.md"
title: "FastAPI Security Deep Dive"
heading: "5. Real CVEs / Vulnerabilities"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, explanation, language-vuln, overview, python, secure, vulnerability, vulnerable]
chunk: 7/10
---

## 5. Real CVEs / Vulnerabilities

### CVE-2026-2977 — FastApiAdmin Unrestricted Upload (RCE via Scheduled Task API)

| Field | Value |
|-------|-------|
| **CVSS** | 8.8 (High) — NIST / 6.3 (Medium) — VulDB |
| **CWE** | CWE-284 (Improper Access Control), CWE-434 (Unrestricted Upload) |
| **Affected** | FastApiAdmin ≤ 2.2.0 |
| **Published** | 2026-02-23 |
| **Type** | Unrestricted File Upload → RCE |

**Description:** A security vulnerability in FastApiAdmin up to version 2.2.0 affects the `upload_controller` function in `/backend/app/api/v1/module_common/file/controller.py` (Scheduled Task API component). Manipulation of the upload functionality leads to unrestricted upload of files with dangerous types, allowing remote code execution. The exploit has been publicly disclosed.

**Impact:** An authenticated attacker (requires low-privilege access) can upload arbitrary files to the server, including Python scripts or shell scripts that get executed by the scheduled task system, leading to full server compromise.

**Fix:** Upgrade to FastApiAdmin > 2.2.0. Restrict upload paths, validate file types server-side, and never allow uploaded files to be executed as code.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-2977

---

### CVE-2026-2978 — FastApiAdmin Unrestricted Upload (Second Vector)

| Field | Value |
|-------|-------|
| **CVSS** | 8.8 (High) — NIST / 6.3 (Medium) — VulDB |
| **CWE** | CWE-284 (Improper Access Control), CWE-434 (Unrestricted Upload) |
| **Affected** | FastApiAdmin ≤ 2.2.0 |
| **Published** | 2026-02-23 |
| **Type** | Unrestricted File Upload → RCE |

**Description:** A second unrestricted upload vulnerability in FastApiAdmin ≤ 2.2.0, this time in the `upload_file_controller` function in `/backend/app/api/v1/module_system/params/controller.py` (Scheduled Task API). Like CVE-2026-2977, this allows remote code execution via crafted file uploads.

**Impact:** Same as CVE-2026-2977 — full server compromise via file upload RCE.

**Fix:** Upgrade to FastApiAdmin > 2.2.0. Implement file type validation, size limits, and path sanitization.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-2978

---

### CVE-2026-48710 — Starlette BADHOST: Host-Header Auth Bypass (CRITICAL for FastAPI)

| Field | Value |
|-------|-------|
| **CVSS** | 6.5 (Medium) — CNA / 7.0 (High) — X41 D-Sec |
| **CWE** | CWE-444 (HTTP Request Smuggling), CWE-1289 (Improper Validation) |
| **Affected** | Starlette < 1.0.1 (all FastAPI installations on Starlette ≤ 1.0.0) |
| **Published** | 2026-05-26 |
| **Type** | Authentication Bypass → Potential RCE |

**Description:** A critical vulnerability in Starlette's HTTP request handling. The `Host` request header was not validated before being used to reconstruct `request.url`. Because Starlette's routing algorithm relies on the raw HTTP path while `request.url` is rebuilt from the `Host` header, a malformed header (containing `/`, `?`, or `#`) can make `request.url.path` differ from the path that was actually requested. Middleware and endpoints that apply security restrictions based on `request.url` (rather than the raw `scope` path) can be bypassed.

A single malformed character in the `Host` header lets an attacker slip past access controls. X41 D-Sec demonstrated changing a 403 Forbidden response to 200 OK by adding one character to the `Host` header.

**Downstream Impact:** This vulnerability affects:
- All FastAPI applications running on Starlette ≤ 1.0.0
- Model-serving tools (LiteLLM, vLLM, OpenRouter proxies)
- API gateways, eval frameworks, agent frameworks, and MCP servers built on FastAPI
- Directly-exposed ASGI servers (no compliant reverse proxy)

**Fix:** Upgrade to Starlette ≥ 1.0.1. Starlette 1.0.1 validates the `Host` header against RFC 9112 §3.2 / RFC 3986 §3.2.2 and falls back to `scope["server"]` for malformed values.

**Mitigation:** Deploy behind a compliant reverse proxy (nginx, Apache HTTPD, HAProxy) that rejects malformed `Host` headers before they reach the application.

> **⚠️ CRITICAL NOTE:** As of May 2026, this vulnerability has received widespread attention because it affects "most of the model-serving, gateway, proxy, eval, agent, and MCP-server infrastructure that has been stood up in the last two years" (Secwest advisory). The CSO Online article warns that AI tooling built on FastAPI is the primary attack surface.

**References:**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-48710
- GHSA: https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr
- X41 D-Sec: https://www.x41-dsec.de/lab/advisories/x41-2026-002-starlette
- OSTIF: https://ostif.org/disclosing-the-badhost-vulnerability-in-starlette
- CSO Online: https://www.csoonline.com/article/4177711/fastapi-based-ai-tools-exposed-to-authentication-bypass-by-flaw-in-starlette-framework.html
- Test tool: https://badhost.org

---

### CVE-2026-48817 — Starlette HTTPEndpoint Unsafe Reflection

| Field | Value |
|-------|-------|
| **CVSS** | 5.3 (Medium) — GitHub |
| **CWE** | CWE-470 (Unsafe Reflection) |
| **Affected** | Starlette ≤ 1.0.1 |
| **Published** | 2026-06-17 |
| **Type** | Unsafe Reflection → Authorization Bypass |

**Description:** When dispatching a request, `HTTPEndpoint` selects the handler by lowercasing the HTTP method and using `getattr()` to look it up as an attribute — without restricting the lookup to a known set of HTTP verbs. When an `HTTPEndpoint` subclass is registered through `Route(...)` without an explicit `methods=` argument, every method reaches the endpoint. If a non-standard HTTP method whose lowercased name matches an attribute on the endpoint subclass reaches the endpoint, that attribute is invoked as if it were a request handler. An attacker can reach internal helper methods that were never meant to be HTTP handlers, bypassing authorization checks.

**Impact:** Authorization bypass for internal endpoint methods. Attackers can call private methods by sending unusual HTTP verbs.

**Fix:** Upgrade to Starlette ≥ 1.1.0.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-48817

---

### CVE-2025-62727 — Starlette FileResponse DoS via Range Header

| Field | Value |
|-------|-------|
| **CVSS** | 7.5 (High) — GitHub |
| **CWE** | CWE-407 (Inefficient Algorithmic Complexity) |
| **Affected** | Starlette 0.39.0 — 0.49.1 |
| **Published** | 2025-10-28 |
| **Type** | Denial of Service |

**Description:** An unauthenticated attacker can send a crafted HTTP `Range` header that triggers quadratic-time processing in Starlette's `FileResponse` range parsing/merging logic. This enables CPU exhaustion per request, causing denial of service for endpoints serving files (e.g., `StaticFiles` or any use of `FileResponse`).

**Impact:** CPU exhaustion DoS on endpoints serving static files or using `FileResponse`.

**Fix:** Upgrade to Starlette ≥ 0.49.1.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-62727

---

### CVE-2021-32677 — FastAPI CSRF via JSON Content-Type Bypass

| Field | Value |
|-------|-------|
| **CVSS** | 8.1 (High) — NIST |
| **CWE** | CWE-352 (Cross-Site Request Forgery) |
| **Affected** | FastAPI < 0.65.2 |
| **Published** | 2021-06-09 |
| **Type** | CSRF |

**Description:** FastAPI versions below 0.65.2 that used cookies for authentication in path operations receiving JSON payloads were vulnerable to CSRF. FastAPI would try to read the request payload as JSON even if the content-type header was `text/plain`. Since `text/plain` requests are exempt from CORS preflights (Simple requests), browsers would execute them with cookies included. The JSON content would be parsed and accepted by the FastAPI application.

**Impact:** Cookie-based authentication can be bypassed. An attacker hosting a malicious page can trigger authenticated state-changing operations on the victim's FastAPI application.

**Fix:** Upgrade to FastAPI ≥ 0.65.2. The fix requires `application/json` or compatible JSON media types for JSON body parsing.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-32677

---

### CVE-2026-24486 — Python-Multipart Path Traversal (Affects FastAPI File Uploads)

| Field | Value |
|-------|-------|
| **CVSS** | 7.5 (High) — NIST / 8.6 (High) — GitHub |
| **CWE** | CWE-22 (Path Traversal) |
| **Affected** | python-multipart < 0.0.22 |
| **Published** | 2026-01-26 |
| **Type** | Path Traversal → Arbitrary File Write |

**Description:** A path traversal vulnerability in python-multipart (the library FastAPI uses for parsing multipart form data, including file uploads) when using non-default configuration options `UPLOAD_DIR` and `UPLOAD_KEEP_FILENAME=True`. An attacker can write uploaded files to arbitrary locations on the filesystem by crafting a malicious filename containing `../` sequences.

**Impact:** Any FastAPI application using python-multipart's `UPLOAD_DIR` and `UPLOAD_KEEP_FILENAME=True` is vulnerable to arbitrary file write, potentially leading to RCE (e.g., overwriting application code or writing to cron directories).

**Fix:** Upgrade to python-multipart ≥ 0.0.22. Workaround: avoid using `UPLOAD_KEEP_FILENAME=True`.

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-24486

---

### Ecosystem CVE Summary

| CVE | Component | Severity | Type | Fixed In |
|-----|-----------|----------|------|----------|
| CVE-2026-2977 | FastApiAdmin | 8.8 High | Unrestricted Upload → RCE | > 2.2.0 |
| CVE-2026-2978 | FastApiAdmin | 8.8 High | Unrestricted Upload → RCE | > 2.2.0 |
| CVE-2026-48710 | Starlette | 6.5 Medium* | Auth Bypass (BADHOST) | ≥ 1.0.1 |
| CVE-2026-48817 | Starlette | 5.3 Medium | Unsafe Reflection Auth Bypass | ≥ 1.1.0 |
| CVE-2025-62727 | Starlette | 7.5 High | DoS via Range Header | ≥ 0.49.1 |
| CVE-2021-32677 | FastAPI | 8.1 High | CSRF via JSON | ≥ 0.65.2 |
| CVE-2026-24486 | python-multipart | 7.5 High | Path Traversal | ≥ 0.0.22 |
| CVE-2021-29510 | Pydantic | 5.3 Medium | Infinity/NaN Validation Bypass | ≥ 1.8.2 |

*\* CVE-2026-48710 is rated 7.0 (High) by X41 D-Sec and Secwest, who note it materially understates the downstream impact on AI infrastructure.*

---