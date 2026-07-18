---
source: "languages/typescript/nestjs-security.md"
title: "NestJS Security (TypeScript)"
heading: "Vibe-Coding Red Flags"
category: "language-vuln"
language: "typescript"
severity: "high"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 7/7
---

## Vibe-Coding Red Flags

- No `ValidationPipe` configured globally — **Red Flag #1**
- `origin: '*'` + `credentials: true` — **Critical misconfiguration**
- Services using raw `repository.save(body)` with entity as DTO — **Mass assignment**
- `@Public()` decorator on more than a few endpoints — **Overexposure**
- No `@UseGuards()` on controller classes — **No auth protection**
- Entity/Model classes imported directly into controllers — **DTOs should be separate**
- `TypeORM synchronize: true` in `NODE_ENV=production` — **Risk of data loss**
- No rate limiting on login/register endpoints — **Brute-force attack surface**
- `FileTypeValidator` as sole file validation — **MIME type bypass**
- `@Req() user` used without a preceding guard check — **User may be undefined**
- No security headers (Helmet) — **Missing CSP, HSTS, X-Frame-Options**
- No CSRF protection for cookie-based auth — **State-changing requests can be forged**
- Error messages exposing internal details — **Information leakage**