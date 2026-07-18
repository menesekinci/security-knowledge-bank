---
source: "languages/java/spring-security-deep.md"
title: "Spring Security Deep Dive"
heading: "10. Common AI-Produced Misconfigurations"
category: "language-vuln"
language: "java"
severity: "high"
tags: [chain, configuration, cors, cve-2025-41248, filter, java, language-vuln, oauth2, overview, pitfalls]
chunk: 12/13
---

## 10. Common AI-Produced Misconfigurations

1. **`@PreAuthorize` on generic base classes** — Annotation bypass on parameterized types (CVE-2025-41248)
2. **`cors().disable()` in Spring Security** — Overriding MVC CORS configuration
3. **`*` allowedOrigins with `allowCredentials(true)`** — Illegal CORS combination
4. **Filter chains without `@Order`** — Non-deterministic chain ordering
5. **`csrf().disable()` on non-API apps** — Disabling CSRF for stateful apps
6. **`sessionFixation().none()`** — Missing session fixation protection
7. **OAuth2 with open redirect** — Unsafe redirect_uri handling
8. **Client secret hardcoded** — OAuth2 credentials in source code
9. **`headers().disable()`** — Missing all security headers
10. **`permitAll()` before authentication** — Public access to unauthenticated routes

---