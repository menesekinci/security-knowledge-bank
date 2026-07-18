---
source: "languages/javascript/angular-security.md"
title: "Angular Security Deep Dive"
heading: "5. Real CVEs (Verified via NVD)"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 7/10
---

## 5. Real CVEs (Verified via NVD)

### CVE-2026-27739 — SSRF in Angular SSR
- **Published:** 2026-02-25
- **CVSS:** Not yet assigned (NVD analysis pending)
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Affected:** Angular SSR `@angular/ssr` prior to 21.2.0-rc.1, 21.1.5, 20.3.17, 19.2.21
- **Description:** The Angular SSR request handling pipeline does not properly validate internally reconstructed URLs. An attacker can craft a request that triggers Angular's internal URL reconstruction to point to an arbitrary host, enabling SSRF. This allows accessing internal cloud metadata endpoints (e.g., `http://169.254.169.254/`), internal services, and otherwise protected infrastructure.
- **Fix:** Upgrade to `@angular/ssr` >= 21.2.0-rc.1, 21.1.5, 20.3.17, or 19.2.21. Server-side URL reconstruction now validates against the application's allowed origins.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-27739

### CVE-2026-54264 — Information Disclosure in Angular Service Worker
- **Published:** 2026-06-22
- **CVSS:** Not yet assigned (NVD analysis pending)
- **CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Affected:** `@angular/service-worker` prior to 22.0.1, 21.2.17, 20.3.25
- **Description:** When the Angular Service Worker fetches assets, it preserves metadata (such as headers) from the original request. An attacker who can observe cached responses or exploit a Service Worker scope mismatch may be able to infer sensitive response headers or cached data.
- **Fix:** Upgrade to `@angular/service-worker` >= 22.0.1, 21.2.17, or 20.3.25. The Service Worker now sanitizes response metadata before caching.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-54264

### CVE-2026-54268 — Denial of Service in Angular DatePipe
- **Published:** 2026-06-22
- **CVSS:** Not yet assigned (NVD analysis pending)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Affected:** `@angular/common` prior to 22.0.1, 21.2.17, 20.3.25
- **Description:** The `formatDate` function (and the standard Angular DatePipe) does not properly limit or validate the length of format strings. An attacker can provide an extremely long or deeply nested format pattern that causes the date formatter to consume excessive CPU and memory, leading to application-level denial of service.
- **Fix:** Upgrade to Angular >= 22.0.1, 21.2.17, or 20.3.25. Format strings are now length-limited and pattern-validated.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-54268

---