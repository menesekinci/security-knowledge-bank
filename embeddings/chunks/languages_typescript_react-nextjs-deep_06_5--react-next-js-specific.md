---
source: "languages/typescript/react-nextjs-deep.md"
title: "React/Next.js Deep Security — AI-Generated Code Edition"
heading: "5. React/Next.js Specific Vulnerabilities (Verified CVEs)"
category: "language-vuln"
language: "typescript"
severity: "critical"
tags: [code, explanation, language-vuln, next, react, secure, typescript, vulnerability, vulnerable]
chunk: 6/10
---

## 5. React/Next.js Specific Vulnerabilities (Verified CVEs)

### CVE-2025-55182 — React RSC RCE ("React2Shell")

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL — CVSS 10.0 |
| **Type** | Pre-authentication Remote Code Execution |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **Affected** | React 19.0.0–19.2.0; Next.js 14.x–15.x (RSC) |
| **Fixed in** | React 19.0.4+ / 19.1.5+ / 19.2.4+; Next.js 15.1.9+ / 15.2.6+ / 15.3.6+ / 15.4.8+ / 15.5.7+ |
| **Exploitation** | Actively exploited in the wild within 48 hours of disclosure |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2025-55182 |

**Root Cause:** Unsafe deserialization in the React Server Components "Flight" protocol. Crafted HTTP requests to Server Function endpoints bypassed all authentication and achieved arbitrary code execution on the server.

**AI Connection:** AI-generated Next.js apps are especially vulnerable because they often use the default RSC setup without understanding the deserialization boundary. The `'use server'` directive automatically creates endpoints that AI does not secure.

### CVE-2025-29927 — Next.js Middleware Authorization Bypass

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL — CVSS 9.1 |
| **Type** | Authorization Bypass |
| **CWE** | CWE-285 / CWE-863 (Improper/Incorrect Authorization) |
| **Affected** | Next.js 11.1.4–15.2.2 |
| **Fixed in** | 12.3.5, 13.5.9, 14.2.25, 15.2.3 |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2025-29927 |

**Root Cause:** The internal `x-middleware-subrequest` header, used to prevent infinite middleware recursion, was client-controllable. Sending `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` caused Next.js to skip all middleware execution — including authentication checks, CSP headers, and geolocation guards.

**AI Connection:** AI-generated code commonly puts ALL authentication logic solely in middleware. This CVE demonstrates why middleware-only auth is catastrophic. AI rarely generates defense-in-depth with server-side auth in handlers.

### CVE-2025-57822 — Next.js SSRF via next()

| Field | Value |
|-------|-------|
| **Severity** | HIGH — CVSS 8.2 (NIST) / 6.5 (GitHub) |
| **Type** | Server-Side Request Forgery (SSRF) |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **Affected** | Next.js < 14.2.32, < 15.4.7 |
| **Fixed in** | 14.2.32, 15.4.7 |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2025-57822 |

**Root Cause:** When `next()` was called without explicitly passing the request object in self-hosted Next.js environments, user-supplied headers could be forwarded to internal services, enabling SSRF attacks.

**AI Connection:** AI generated middleware and route handlers often use `next()` without the request parameter, especially in custom middleware patterns for self-hosted deployments.

### CVE-2026-23864 — React RSC Denial of Service

| Field | Value |
|-------|-------|
| **Severity** | HIGH — CVSS 7.5 |
| **Type** | Denial of Service (DoS) |
| **CWE** | CWE-400 / CWE-502 / CWE-1284 |
| **Affected** | React 19.0.0–19.2.x |
| **Fixed in** | 19.0.4+, 19.1.5+, 19.2.4+ |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2026-23864 |

**Root Cause:** Multiple uncontrolled resource consumption vectors in the React Server Components Flight protocol. Specially crafted HTTP requests to Server Function endpoints caused server crashes, OOM exceptions, or excessive CPU usage.

### CVE-2024-34351 — Next.js Server Actions SSRF

| Field | Value |
|-------|-------|
| **Severity** | HIGH — CVSS 7.5 |
| **Type** | Server-Side Request Forgery (SSRF) |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **Affected** | Next.js 13.4.0–14.1.0 |
| **Fixed in** | 14.1.1 |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2024-34351 |

**Root Cause:** Modifying the `Host` header allowed SSRF when Server Actions performed redirects to relative paths. An attacker could make requests appearing to originate from the Next.js server itself.

---

### CVE Cross-Reference Table

| CVE | CVSS | Type | Affected | Fixed | AI Risk |
|-----|------|------|----------|-------|---------|
| CVE-2025-55182 | 10.0 | RCE (RSC Flight) | React 19.0–19.2, Next 14–15 | React 19.0.4+, Next 15.1.9+ | Very High |
| CVE-2025-29927 | 9.1 | Auth Bypass | Next 11.1.4–15.2.2 | 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 | Very High |
| CVE-2025-57822 | 8.2 | SSRF | Next < 14.2.32, < 15.4.7 | 14.2.32 / 15.4.7 | Medium |
| CVE-2026-23864 | 7.5 | DoS | React 19.0–19.2 | 19.0.4+ / 19.1.5+ / 19.2.4+ | Medium |
| CVE-2024-34351 | 7.5 | SSRF (Server Actions) | Next 13.4.0–14.1.0 | 14.1.1 | High |

> **Note:** CVE-2025-66478 was **rejected** as a duplicate of CVE-2025-55182.

---