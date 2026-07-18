---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
heading: "12. Common AI-Produced Misconfigurations"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2025-55182, cve-2025-66478, dangerouslysetinnerhtml, injection, javascript, language-vuln, overview, risks]
chunk: 14/15
---

## 12. Common AI-Produced Misconfigurations

1. **`dangerouslySetInnerHTML` without DOMPurify** — Forgetting to sanitize HTML
2. **Missing auth in Server Actions** — No session check before mutations
3. **NEXT_PUBLIC_ prefix on secrets** — Client-side exposure of API keys
4. **Missing authorization in Route Handlers** — API routes without auth
5. **User-controlled component rendering** — `user.component` as JSX component
6. **`javascript:` URLs in href** — Not validating URL protocols
7. **SSR leaking sensitive data** — Password hashes in server component props
8. **Insecure cookies** — Missing `httpOnly`, `secure`, `sameSite` flags
9. **No input validation in Server Actions** — Direct FormData to database
10. **Disabling CSP** — Setting `Content-Security-Policy` too permissive

---