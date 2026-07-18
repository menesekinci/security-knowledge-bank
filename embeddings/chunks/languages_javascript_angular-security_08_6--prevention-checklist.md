---
source: "languages/javascript/angular-security.md"
title: "Angular Security Deep Dive"
heading: "6. Prevention Checklist"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 8/10
---

## 6. Prevention Checklist

- [ ] **Never use `bypassSecurityTrustHtml`, `bypassSecurityTrustUrl`, `bypassSecurityTrustResourceUrl`, or `bypassSecurityTrustScript` with user-controlled input.** Use `DomSanitizer.sanitize()` with the appropriate `SecurityContext` instead.
- [ ] **Use HTTP interceptors** for all authenticated requests — never manually attach auth headers in individual services.
- [ ] **Store secrets server-side only.** `environment.ts` is client-bundled — use a Backend for Frontend (BFF) proxy for any API keys or tokens.
- [ ] **Guard all routes** — apply `canActivate` AND `canActivateChild` to every protected route. Use functional guards (`CanActivateFn`) for type safety.
- [ ] **Audit all reactive forms** — every `FormControl` should have appropriate validators (`Validators.required`, `Validators.pattern`, `Validators.maxLength`, custom validators).
- [ ] **Expose RxJS Subjects as `Observable`** (`.asObservable()`), not as public `Subject` or `BehaviorSubject`.
- [ ] **Unsubscribe from Observables** — use the `takeUntil` pattern with a destroy-subject or Angular's `async` pipe.
- [ ] **Enable XSRF protection** — Angular's `HttpClientXsrfModule` provides CSRF tokens; ensure it's configured and the server validates them.
- [ ] **Lock down Angular Universal/SSR** — validate incoming request URLs, don't reconstruct URLs from user input, use `isPlatformServer` guards, and sanitize headers passed to `renderModule()`.
- [ ] **Set `Content-Security-Policy` headers** — block inline scripts and `eval()`: `script-src 'self'; object-src 'none'`.
- [ ] **Disable source maps in production** — set `sourceMap: false` in `angular.json` production config to prevent source code exposure.
- [ ] **Use `HttpClient` with type-safe responses** — always specify the expected type: `this.http.get<MyInterface>(url)`.
- [ ] **Enable `strictTemplates`** in `tsconfig.json` — catches template binding errors at compile time.
- [ ] **Audit third-party Angular packages** — supply-chain attacks targeting Angular libraries can inject malicious scripts into the client bundle.
- [ ] **Pin Angular version** — subscribe to Angular security advisories and update promptly when CVEs are disclosed.

---