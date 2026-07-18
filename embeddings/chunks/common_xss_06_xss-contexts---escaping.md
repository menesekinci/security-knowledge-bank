---
source: "common/xss.md"
title: "Cross-Site Scripting (XSS) — Reflected, Stored, DOM-based, CSP Bypass"
heading: "XSS Contexts & Escaping"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, content, contexts, security, types, vibe, what]
chunk: 6/10
---

## XSS Contexts & Escaping

Different HTML contexts require **different escaping**:

| Context | Encoding | Example |
|---|---|---|
| HTML body content | HTML entity encode (`&lt;`, `&gt;`) | `escape()` in Python, `escapeHtml()` in JS |
| HTML attributes | Attribute encode (`"` → `&quot;`, `'` → `&#x27;`) | Must quote attrs and escape quotes |
| JavaScript string | Unicode escape (`\x3C`, `\u003C`) | Never put untrusted data in JS |
| URL parameter | URL encode (`%3C`) | `encodeURIComponent()` |
| CSS | CSS escape (`\3C`) | Avoid untrusted data in CSS entirely |

---