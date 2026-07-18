---
source: "common/xss.md"
title: "Cross-Site Scripting (XSS) — Reflected, Stored, DOM-based, CSP Bypass"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, content, contexts, security, types, vibe, what]
chunk: 8/10
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Stored XSS in WordPress Core Avatar block (user display name) | CVE-2024-4439 | Unauthenticated injection via comment-author avatar; session/account takeover (WP < 6.5.2) |
| Reflected XSS in WordPress Advanced Custom Fields plugin | CVE-2023-30777 | Unauthenticated `post_status` reflection hijacks admin sessions (2M+ sites, ACF ≤ 6.1.5) |
| Stored XSS in Grafana Unified Alerting | CVE-2022-31097 | Injected script escalates an editor to admin when an admin views it |
| DOM XSS via jQuery DOM-manipulation methods (`.html()`, `.append()`) | CVE-2020-11022 | Untrusted HTML executes even after sanitization (jQuery ≥ 1.12.0, < 3.5.0) |
| Stored XSS in CKEditor 4 HTML processing (WYSIWYG) | CVE-2022-24728 | Malformed HTML bypasses the sanitizer, running arbitrary JS in the editor context (< 4.18.0) |
| Stored XSS in Live Helper Chat | CVE-2022-1234 | Page defacement, account compromise, malicious code execution (< 3.97) |

---