---
source: "languages/javascript/css-injection.md"
title: "CSS Injection and Data Exfiltration"
heading: "Overview"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [chrome, cve-2026-2441, cve-2026-26000, exfiltration, injection, javascript, language-vuln, overview, xwiki]
chunk: 2/8
---

## Overview

CSS injection is often underestimated as a "harmless" vulnerability — after all, CSS can't execute code, right? Wrong. CSS can:

1. **Exfiltrate sensitive data** via attribute selectors and URL-backed properties
2. **Bypass Content Security Policy** (since CSS is trusted more than JS)
3. **Create timing oracles** via CSS animations and resource loading
4. **Perform cross-site search** via `@import` with URL fragments
5. **Leak CSRF tokens** character-by-character using attribute selectors

CSS attacks work by using CSS selectors as **oracles**: a selector either matches (loading a resource) or doesn't match (no request), creating a binary side channel.

---