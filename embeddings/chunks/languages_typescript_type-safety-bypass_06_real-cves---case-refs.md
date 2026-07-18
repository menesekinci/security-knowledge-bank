---
source: "languages/typescript/type-safety-bypass.md"
title: "🟡 TypeScript Type Safety Bypass"
heading: "Real CVEs / Case Refs"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 6/8
---

## Real CVEs / Case Refs

| CVE | Product | Score | Type | Description | Source |
|-----|---------|-------|------|-------------|--------|
| CVE-2026-25049 | n8n | 9.4 CRITICAL | Type Confusion → RCE | TypeScript `input: string` annotation used as sole security boundary. Object input bypassed sanitizer entirely, leading to sandbox escape and arbitrary code execution. Bypassed a fix for CVE-2025-68613. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25049), [Analysis](https://hetmehta.com/posts/n8n-type-confusion-rce/), [Endor Labs](https://www.endorlabs.com/learn/cve-2026-25049-n8n-rce) |
| CVE-2025-68613 | n8n | 9.9 CRITICAL | Expression Injection → RCE | Server-side expression evaluation sandbox escape. JavaScript expressions in `{{ }}` blocks could access `this` — the Node.js global object — and execute `require('child_process').execSync()`. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-68613), [Resecurity](https://www.resecurity.com/blog/article/cve-2025-68613-remote-code-execution-via-expression-injection-in-n8n-2), [CVE.org](https://www.cve.org/CVERecord?id=CVE-2025-68613) |

### Why These Matter for TypeScript Developers

The n8n CVEs are a **direct warning** to every TypeScript developer: treating the type system as a security boundary is dangerous. The original CVE-2025-68613 was patched by adding sanitization to the string-based expression input. The type annotation `input: string` gave developers a false sense of security. At runtime, JavaScript cheerfully accepted `{constructor: {prototype: {isAdmin: true}}}` — an object, not a string — and the sanitizer that only ran on strings was skipped entirely.

**Lesson:** TypeScript's type system is a developer tool, not a security control. Every security-critical boundary requires **runtime** enforcement.

---