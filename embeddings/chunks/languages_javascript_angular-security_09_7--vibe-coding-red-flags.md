---
source: "languages/javascript/angular-security.md"
title: "Angular Security Deep Dive"
heading: "7. Vibe-Coding Red Flags (Angular-Specific)"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 9/10
---

## 7. Vibe-Coding Red Flags (Angular-Specific)

Watch for these patterns in AI-generated Angular code:

- [ ] **`bypassSecurityTrustHtml`** — Nearly always a red flag. Search every usage.
- [ ] **`environment.ts` files with API keys, Firebase configs, or Stripe secrets** — Guarantee of credential exposure in bundles.
- [ ] **Missing `HTTP_INTERCEPTORS` provider** — No centralized auth means inconsistent (or absent) authentication.
- [ ] **`canActivate: [AuthGuard]` without `canActivateChild`** — Child routes remain unprotected.
- [ ] **Route guard that calls `this.auth.isLoggedIn()` (immediately returns boolean)** — Does not handle token refresh or Observable pipelines.
- [ ] **Public `Subject` or `BehaviorSubject`** — External code can call `.next()` and inject arbitrary data.
- [ ] **`take(1)` or `first()` inside `ngOnInit` subscriptions without cleanup** — Memory leaks in long-lived components.
- [ ] **Calling `new HttpClient()` instead of injecting it** — Breaks interceptor chain.
- [ ] **`patchValue()` with entire API response objects** — Mass assignment vulnerability.
- [ ] **`innerHTML` or `outerHTML` in `@Component` templates** — Angular will not sanitize binding to these properties the same way as `[innerHTML]`.
- [ ] **`constructor(private el: ElementRef)` with direct DOM manipulation** — SSR-incompatible and bypasses Angular security.
- [ ] **`renderModule()` calls with user-controlled URL parameters** — SSRF vector.
- [ ] **No `Content-Security-Policy` in Angular app** — No defense-in-depth against XSS.
- [ ] **`*ngFor` with user-controlled data and `[innerHTML]`** — XSS in list rendering.
- [ ] **Custom `safe` pipe that wraps `bypassSecurityTrustHtml`** — Deceptively named, equally dangerous.
- [ ] **`catchError` returning `of(false)` in route guard** — Navigates away but does not redirect; user sees blank page instead of login.
- [ ] **`ViewChild` with `static: true` used before data loads** — Race conditions leading to undefined or injected content.
- [ ] **`HttpClient` calls without `.pipe()` for error handling** — Unhandled errors surface stack traces to users.
- [ ] **`window.localStorage` for JWT tokens** — Stolen by any XSS. Prefer `HttpOnly` cookies.
- [ ] **Providing `APP_INITIALIZER` that fetches secrets** — Secrets still in client bundle memory.

---