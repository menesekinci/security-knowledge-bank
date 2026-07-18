---
source: "languages/typescript/nestjs-security.md"
title: "NestJS Security (TypeScript)"
heading: "Real CVEs / Case Refs"
category: "language-vuln"
language: "typescript"
severity: "high"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 6/7
---

## Real CVEs / Case Refs

| CVE | Component | Score | Type | Description | Source |
|-----|-----------|-------|------|-------------|--------|
| CVE-2024-29409 | `@nestjs/common` (FileTypeValidator) | 5.5 MEDIUM | Code Injection / File Upload Bypass | Improper MIME type validation — `FileTypeValidator` only checks the `Content-Type` header, not actual file content. Attacker can upload `.html` files as `image/jpeg` by forging the header. Fixed in 10.4.16 / 11.0.16. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-29409), [Snyk](https://security.snyk.io/vuln/SNYK-JS-NESTJSCOMMON-9538801), [Analysis](https://gist.github.com/aydinnyunus/801342361584d1491c67a820a714f53f) |
| CVE-2023-26108 | `@nestjs/core` (StreamableFile) | 5.3 MEDIUM | Information Exposure | When a client cancels a request during stream of a `StreamableFile`, the underlying stream is kept open — exposing file descriptors and potentially leaking sensitive data. Fixed in 9.0.5. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-26108), [Snyk](https://security.snyk.io/vuln/SNYK-JS-NESTJSCORE-2869127), [Patch](https://github.com/nestjs/nest/pull/9819) |
| CVE-2026-3304 | `@nestjs/platform-express` | HIGH | Dependency Vulnerability | Multer (file upload middleware) dependency in platform-express had a DoS vulnerability. Express v11 users on Multer <2.1.0 vulnerable to connection-drop DoS. | [GitHub Issue](https://github.com/nestjs/nest/issues/16484), [Express Security Release](https://expressjs.com/en/blog/2026-02-27-security-releases/) |
| CVE-2026-35515 | NestJS Framework | — | XSS | Cross-site scripting vulnerability in NestJS framework affecting Server-Sent Events (SSE) processing. Attackers can inject arbitrary SSE content. | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-35515/) |
| CVE-2026-40879 | Nest.js | — | Buffer Overflow | Buffer overflow vulnerability allowing attackers to trigger call stack overflow via crafted small JSON messages. | [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-40879/) |
| ValidationPipe PP | `@nestjs/common` (ValidationPipe) | HIGH (unassigned) | Prototype Pollution | `stripProtoKeys()` only stripped `__proto__` but not `constructor` or `prototype`. Attacker could send `{constructor: {prototype: {isAdmin: true}}}` to pollute `Object.prototype`. Fixed in PR #16079. | [GitHub Issue #16050](https://github.com/nestjs/nest/issues/16050), [Fix PR #16079](https://github.com/nestjs/nest/pull/16079) |

### Key NestJS Security Resources

- [NestJS Validation Documentation](https://docs.nestjs.com/techniques/validation) — Official `ValidationPipe` guide with whitelist/transform options
- [NestJS CORS Documentation](https://docs.nestjs.com/security/cors) — Official CORS configuration guide
- [NestJS Helmet Documentation](https://docs.nestjs.com/security/helmet) — Security headers best practices
- [OWASP API Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) — API security risks relevant to NestJS
- [Snyk: Avoiding Mass Assignment in Node.js](https://snyk.io/blog/avoiding-mass-assignment-node-js/) — Mass assignment patterns and fixes

---