---
source: "languages/javascript/svelte-security.md"
title: "Svelte & SvelteKit Security Deep Dive"
heading: "5. Real CVEs (Verified via NVD)"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 7/10
---

## 5. Real CVEs (Verified via NVD)

### CVE-2022-25875 — XSS in Svelte SSR
- **Published:** 2022-07-12
- **CVSS:** 6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
- **CWE:** CWE-79 (Cross-site Scripting)
- **Affected:** Svelte < 3.49.0
- **Description:** During Server-Side Rendering (SSR), Svelte does not properly escape attribute values when objects with a custom `toString()` function are used. An attacker can craft an object that, when rendered during SSR, injects arbitrary HTML/JavaScript into the server-rendered HTML. This bypasses Svelte's compile-time escaping guarantees because the escaping happens at runtime during SSR.
- **Fix:** Upgrade to Svelte >= 3.49.0. The SSR attribute escaping was rewritten to properly handle `toString()` returns.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2022-25875

### CVE-2023-29003 — CSRF Bypass in SvelteKit
- **Published:** 2023-04-04
- **CVSS:** 8.8 HIGH (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **Affected:** SvelteKit < 1.15.1
- **Description:** SvelteKit's built-in CSRF protection checks the `Content-Type` header to determine if a request is a form submission. The `is_form_content_type` function only checked for `application/x-www-form-urlencoded` and `multipart/form-data`. An attacker can submit a `POST` request with `text/plain` content type — which browsers allow cross-origin — bypassing CSRF protection entirely. SvelteKit 1.15.1 added `text/plain` to the check and extended CSRF validation to `PUT`, `PATCH`, and `DELETE` methods.
- **Fix:** Upgrade to SvelteKit >= 1.15.1.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-29003

### CVE-2023-29008 — CSRF Bypass via Uppercase Content-Type (SvelteKit)
- **Published:** 2023-04-06
- **CVSS:** 8.8 HIGH (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **Affected:** SvelteKit < 1.15.2
- **Description:** SvelteKit's CSRF protection did a case-sensitive comparison of the `Content-Type` header. Browsers will not send an uppercase `Content-Type`, but a fetch-based attacker can set `Content-Type` to `TEXT/PLAIN` or `Application/X-WWW-FORM-URLENCODED`, which bypasses the case-sensitive check. SvelteKit 1.15.2 made the comparison case-insensitive.
- **Fix:** Upgrade to SvelteKit >= 1.15.2.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-29008

### CVE-2023-38687 — XSS in Svelecte (Svelte Component Library)
- **Published:** 2023-08-14
- **CVSS:** 5.4 MEDIUM (AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)
- **CWE:** CWE-79 (Cross-site Scripting)
- **Affected:** Svelecte < 3.16.3
- **Description:** Svelecte, a Svelte autocomplete/select component, renders item names as raw HTML without escaping. An attacker who can control the label of a selectable item can inject arbitrary HTML/JavaScript that executes when the dropdown is opened.
- **Fix:** Upgrade to Svelecte >= 3.16.3.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-38687

### CVE-2021-29261 — RCE in Svelte VS Code Extension
- **Published:** 2021-04-05
- **CVSS:** 7.8 HIGH (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **CWE:** NVD-CWE-noinfo
- **Affected:** Svelte VS Code extension < 104.8.0
- **Description:** The unofficial Svelte language-tools extension for VS Code allowed arbitrary code execution via a crafted workspace configuration. Opening a malicious project could compromise the developer's machine.
- **Fix:** Upgrade to the official Svelte VS Code extension >= 104.8.0.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-29261

---