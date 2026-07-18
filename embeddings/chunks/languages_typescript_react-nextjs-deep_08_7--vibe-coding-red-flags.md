---
source: "languages/typescript/react-nextjs-deep.md"
title: "React/Next.js Deep Security — AI-Generated Code Edition"
heading: "7. Vibe-Coding Red Flags (15 Items)"
category: "language-vuln"
language: "typescript"
severity: "critical"
tags: [code, explanation, language-vuln, next, react, secure, typescript, vulnerability, vulnerable]
chunk: 8/10
---

## 7. Vibe-Coding Red Flags (15 Items)

When reviewing AI-generated React/Next.js code, watch for these patterns:

1. ✅ **`'use client'` on every page** — indicates AI doesn't understand RSC boundaries; most pages should be Server Components
2. ✅ **Middleware as the only auth layer** — AI rarely adds auth inside route handlers or Server Actions
3. ✅ **`as Type` casts without runtime validation** — `const data = await res.json() as User` (no Zod parse)
4. ✅ **Server Actions that accept `formData` and pass it to DB directly** — `Object.fromEntries(formData)` is a mass-assignment red flag
5. ✅ **File uploads to `public/uploads/` or `public/avatars/`** — every AI framework boilerplate does this
6. ✅ **`dangerouslySetInnerHTML` without sanitization** — AI doesn't import DOMPurify or use `dangerouslySetInnerHTML={{ __html: userContent }}`
7. ✅ **No session/ownership check in delete endpoints** — `deletePost(postId)` without verifying `post.authorId`
8. ✅ **`NEXT_PUBLIC_*` with actual secrets** — AI doesn't distinguish public from private env vars
9. ✅ **Open redirect patterns** — `searchParams.get('redirect')` used without validation in redirect logic
10. ✅ **No rate limiting on auth endpoints** — AI generates login/register forms without rate limit checks
11. ✅ **`<Link>` without `rel="noopener noreferrer"`** for external URLs
12. ✅ **Exposing internal API structure** — `/api/users/${userId}` patterns that let attackers enumerate user IDs
13. ✅ **`eval()` or `new Function()` in any form** — AI uses these for dynamic template rendering
14. ✅ **No error boundaries** — unhandled promise rejections in Server Components can leak stack traces
15. ✅ **Old Next.js versions in `package.json`** — AI often pins `"next": "14.0.0"` or `"next": "13.5.0"` without knowing about CVEs

---