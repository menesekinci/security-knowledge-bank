---
source: "languages/typescript/nestjs-security.md"
title: "NestJS Security (TypeScript)"
heading: "Prevention Checklist"
category: "language-vuln"
language: "typescript"
severity: "high"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 5/7
---

## Prevention Checklist

- [ ] **Global `ValidationPipe`** with `whitelist: true`, `forbidNonWhitelisted: true`, `transform: true`
- [ ] **Auth guards default-deny** — Use `@UseGuards(JwtAuthGuard)` at controller level, only `@Public()` on truly open endpoints
- [ ] **CORS allowlist** — Never `origin: '*'` with `credentials: true`. Always specify exact origins
- [ ] **Helmet / security headers** — `app.use(helmet())` with explicit CSP directives
- [ ] **Rate limiting** — Use `@nestjs/throttler` on auth, password reset, and public API endpoints
- [ ] **No entity as `@Body()` type** — Always create separate DTO classes with `class-validator` decorators
- [ ] **CSRF protection** — Enable for cookie-based auth; use `SameSite=Strict` cookies or CSRF tokens
- [ ] **File upload validation** — Never trust `Content-Type` header. Validate file content (magic bytes)
- [ ] **Disable `synchronize: true` in production** — Use TypeORM/Prisma migrations instead
- [ ] **Scope DB queries by authenticated user** — Every query that reads/writes user data must filter by `req.user.id`
- [ ] **Prototype pollution defense** — Ensure `stripProtoKeys` removes `constructor` and `prototype` properties
- [ ] **Disable detailed errors in production** — `disableErrorMessages: true` on ValidationPipe
- [ ] **Use `class-validator` transform decorators** — `@Transform(({value}) => sanitize(value))` for input sanitization
- [ ] **Log security events** — Failed auth attempts, validation failures, unauthorized access attempts

---