---
source: "languages/typescript/nestjs-security.md"
title: "NestJS Security (TypeScript)"
heading: "intro"
category: "language-vuln"
language: "typescript"
severity: "high"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 1/7
---

# NestJS Security (TypeScript)

> **Severity:** High
> **CWE:** CWE-284 (Improper Access Control), CWE-915 (Mass Assignment), CWE-20 (Improper Input Validation), CWE-94 (Code Injection), CWE-200 (Information Exposure), CWE-1321 (Prototype Pollution)
> **AI Generation Risk:** High — open CORS, missing guards, DTO without whitelist, missing rate limiting, unprotected mass assignment

---