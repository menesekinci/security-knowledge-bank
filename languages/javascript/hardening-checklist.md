# 🌐 JavaScript / TypeScript Security Hardening Checklist

> Items to check in every JS/TS project before deployment.

## ✅ General
- [ ] Has `npm audit` been run?
- [ ] Is there a `package-lock.json` / `yarn.lock`?
- [ ] Are dependencies version-pinned? (No `^` ranges used?)
- [ ] Is SRI (Subresource Integrity) being used?

## ✅ Code Security
- [ ] No `eval()`, `new Function()`, `setTimeout(string)`?
- [ ] No `innerHTML` / `outerHTML` / `insertAdjacentHTML` used? (Is DOMPurify present?)
- [ ] If `dangerouslySetInnerHTML` (React) is used, is the input sanitized?
- [ ] No `prototype` manipulation? (Object.prototype, Array.prototype)
- [ ] No `any` / `as any` / `@ts-ignore` used?
- [ ] Any `// @ts-ignore`? — if so, is it justified?

## ✅ Web Security
- [ ] Is there a CSP (Content-Security-Policy) header?
- [ ] Is CORS open only for trusted origins?
- [ ] Is X-Content-Type-Options: nosniff present?
- [ ] Is Helmet.js (Express) being used?
- [ ] Is there CSRF token protection?

## ✅ Authentication
- [ ] Is `verify()` used when decoding JWTs? (not `decode()`)
- [ ] Is there a JWT algorithm whitelist?
- [ ] Is the JWT secret strong? (256+ bit random)
- [ ] Are session cookies `httpOnly` + `secure`?

## ✅ Node.js Specific
- [ ] Do `path.join()` / `path.resolve()` perform path-traversal checks?
- [ ] Is `execFile()` used instead of `child_process.exec()`?
- [ ] Is there SSRF protection? (private IP blocking)
- [ ] Is there path validation in `fs` operations?

## ✅ Build / Deploy
- [ ] Is the `.env` file in gitignore?
- [ ] Are API keys / secrets in environment variables?
- [ ] Are no secrets visible in build logs?
- [ ] Are source maps disabled in production?

## 🛡️ Vibe Coding Extra
- [ ] Have the npm packages suggested by the AI been verified? (download count, last update date)
- [ ] Has the AI's suggested use of `eval`/`innerHTML` been rejected?
- [ ] Have the AI's `any` casts been replaced with type guards?
