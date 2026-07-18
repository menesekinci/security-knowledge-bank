---
source: "common/cors-deep.md"
title: "CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs"
heading: "What Is CORS?"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [coding, common-vuln, cors, headers, vibe, vulnerability, what]
chunk: 2/10
---

## What Is CORS?

Cross-Origin Resource Sharing (CORS) is a browser mechanism that **relaxes the Same-Origin Policy (SOP)** in a controlled way. SOP prevents a web page from one origin from reading resources from another origin. CORS allows servers to explicitly declare which origins are permitted to read their resources.

**The problem:** CORS is frequently misconfigured in ways that allow attackers to exfiltrate sensitive data. AI-generated code is particularly prone to permissive CORS settings because:

- AI uses `*` wildcard to "make things work"
- AI doesn't understand credentials mode implications
- AI reflects the `Origin` header without validation
- AI enables CORS "for development" and it ships to production

---