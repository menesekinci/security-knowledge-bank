---
source: "languages/javascript/angular-security.md"
title: "Angular Security Deep Dive"
heading: "2. How AI Generates These Vulnerabilities"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 4/10
---

## 2. How AI Generates These Vulnerabilities

| Vulnerability Pattern | AI Prompt That Triggers It |
|---|---|
| `bypassSecurityTrustHtml` | "I'm getting SafeValue must use [property]=binding error, fix it" or "render HTML content in Angular" |
| No auth interceptor | "Create an Angular service that calls this API" (no mention of auth) |
| Secrets in `environment.ts` | "Add Firebase/Auth0 config to Angular project" |
| Route guard returns `true` | "Add a route guard for the admin page" (no auth implementation details) |
| Missing form validators | "Create a login form with email and password" (no validation specified) |
| Exposed Subject | "Create a shared service for user data" (AI creates public Subject by default) |
| SSR SSRF | "Add server-side rendering to Angular app" (AI copies bad patterns from forums) |

LLMs trained on Angular tutorials (which often simplify security for demonstration) reproduce those simplifications as production code. Stack Overflow snippets with `bypassSecurityTrustHtml` are overrepresented in training data.

---