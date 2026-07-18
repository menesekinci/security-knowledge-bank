---
source: "common/xss.md"
title: "Cross-Site Scripting (XSS) — Reflected, Stored, DOM-based, CSP Bypass"
heading: "What Is XSS?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, content, contexts, security, types, vibe, what]
chunk: 2/10
---

## What Is XSS?

Cross-Site Scripting (XSS) is a vulnerability where an attacker injects **malicious client-side scripts** into web pages viewed by other users. The injected code runs in the victim's browser **in the context of the trusted application**, allowing the attacker to:

- Steal session cookies and authentication tokens
- Redirect users to phishing sites
- Deface web pages
- Log keystrokes
- Execute actions on behalf of the victim
- Install malware via drive-by downloads

**The root cause:** User-supplied data is included in web page output without proper **context-aware encoding** or sanitization.