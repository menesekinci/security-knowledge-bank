# Angular Security Deep Dive

> **Category:** JavaScript / Angular Security Knowledge Bank  
> **Focus:** DomSanitizer bypass, HttpClient misconfig, route guard bypass, environment.ts secret leakage, RxJS subject leaks, SSR SSRF  
> **Severity:** High  
> **CWE:** CWE-79 (XSS), CWE-284 (Access Control), CWE-200 (Info Exposure), CWE-346 (CORS), CWE-311 (Missing Encryption), CWE-918 (SSRF), CWE-400 (DoS)  
> **AI Generation Risk:** High  
> **Last Updated:** July 2026

---

## Overview

Angular is a full-featured framework from Google, widely used for enterprise SPAs, admin dashboards, and internal tooling — exactly the kind of apps AI code generators (ChatGPT, Claude, Copilot, Cursor) are asked to build. Angular's built-in security (DomSanitizer, HttpClient XSRF, route guards) provides strong defaults, but AI models commonly reach for escape hatches that bypass these protections.

The 2026 Angular vulnerability disclosure wave — including SSRF in Angular SSR (CVE-2026-27739), information disclosure in the Service Worker pipeline (CVE-2026-54264), and DoS via DatePipe (CVE-2026-54268) — demonstrates that the framework's server-side rendering and utility packages have a growing attack surface.

---

## 1. Vulnerability Explanation — Angular-Specific AI Risks

### 1.1 DomSanitizer Bypass (`bypassSecurityTrustHtml`)

Angular's `DomSanitizer` enforces context-aware sanitization: HTML, URL, resource URL, style, and script are treated separately. When AI encounters a "SafeValue must use [property]=binding" error, it frequently reaches for `bypassSecurityTrustHtml()` — the Angular equivalent of React's `dangerouslySetInnerHTML` — to silence the compiler rather than refactoring to proper property binding.

```typescript
// 💀 VULNERABLE — Silences sanitization entirely
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

constructor(private sanitizer: DomSanitizer) {}

displayContent(html: string): SafeHtml {
  return this.sanitizer.bypassSecurityTrustHtml(html);
  // No sanitization — user-controlled HTML executes scripts
}
```

AI models are particularly prone to this pattern when generating rich-text previews, comment sections, or notification components.

### 1.2 HttpClient Without Auth Interceptors

Angular's `HttpClient` does not automatically attach authentication credentials. AI-generated services often call `this.http.get(url)` directly without a shared HTTP interceptor that injects `Authorization` headers or cookies. This leads to:

- Unauthenticated API calls that reveal data
- JWT tokens stored in `localStorage` (vulnerable to XSS) instead of `HttpOnly` cookies
- No CSRF/XSRF token handling

### 1.3 `environment.ts` Secret Exposure

Angular's environment files (`environment.ts`, `environment.prod.ts`) are bundled into the client-side JavaScript. Any value stored there — API keys, Firebase config, Auth0 client secrets, Stripe publishable keys that are treated as secret — is sent to every browser and visible in `window.webpackJsonp` or source maps.

AI models frequently generate:

```typescript
// 💀 VULNERABLE — environment.ts (bundled with client code)
export const environment = {
  production: false,
  apiKey: 'sk-xxxxxxxxxxxxxxxxxxxx',
  firebaseConfig: { /* all secrets here */ },
  stripeSecretKey: 'sk_live_xxxxxxxxx'
};
```

### 1.4 Route Guard Bypass / Misconfiguration

Route guards (`CanActivate`, `CanActivateChild`) control access to Angular routes. AI frequently generates guards that always return `true` (placeholder logic), apply guards only on the `canActivate` array but not on child routes, or import the guard but forget to wire it in the routing module.

```typescript
// 💀 VULNERABLE — Always allows access
@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  canActivate(): boolean {
    return true; // Placeholder — AI forgot auth logic
  }
}
```

AI also commonly generates routes with `canActivate: [AuthGuard]` but leaves `canActivateChild` unguarded, exposing nested routes like `/admin/users/:id/edit`.

### 1.5 Reactive Forms Without Validation

Angular's reactive forms (`FormGroup`, `FormControl`) provide built-in validators. AI models often generate form controls with no validators, or use async validators that are never properly awaited, leading to:

- Server-side injection via unvalidated inputs
- Mass assignment through `patchValue()` with user objects
- Business logic bypass through missing `required`, `maxLength`, or pattern validators

### 1.6 RxJS Security Issues (Subject Leaks, Exposed Observables)

RxJS is central to Angular. AI-generated code commonly:

- Exposes `Subject` or `BehaviorSubject` as public (not as `Observable`), letting consumers call `.next()` and inject data
- Neglects `takeUntil` or `first` for subscriptions in components, causing memory leaks and stale data serving
- Uses `shareReplay(1)` without a `refCount`, creating lingering subscriptions
- Passes user-controlled input directly into `switchMap` callbacks without validation

```typescript
// 💀 VULNERABLE — Public Subject allows external data injection
// @ts-ignore or AI-generated
userSubject = new BehaviorSubject<User>(initialUser);

// SECURE — Expose only as Observable
private userSubject = new BehaviorSubject<User>(initialUser);
user$: Observable<User> = this.userSubject.asObservable();
```

### 1.7 Angular Universal (SSR) Specific Risks

Angular Universal renders pages server-side. AI-generated Universal apps frequently:

- Call `renderModule()` with user-controlled URL paths, leading to SSRF
- Leak server-side state into client bundles via `TransferState`
- Use `DOCUMENT` injection token on the server without `isPlatformServer` guards, causing errors that expose stack traces
- Misconfigure `server.ts` to trust proxy headers without validation, enabling IP spoofing

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

## 3. Vulnerable Code Examples

### 3.1 DomSanitizer XSS

```typescript
// 💀 VULNERABLE
import { Component } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-comment',
  template: `<div [innerHTML]="safeContent"></div>`
})
export class CommentComponent {
  safeContent: SafeHtml;

  constructor(private sanitizer: DomSanitizer) {
    // User input from route param or API — NO SANITIZATION
    this.safeContent = this.sanitizer.bypassSecurityTrustHtml(
      this.getUserInput() // <img src=x onerror=alert('XSS')>
    );
  }
}
```

### 3.2 HTTP Without Auth

```typescript
// 💀 VULNERABLE
@Injectable({ providedIn: 'root' })
export class UserService {
  constructor(private http: HttpClient) {}

  getUsers() {
    // No auth interceptor, no headers
    return this.http.get<User[]>('https://api.example.com/users');
  }
}
```

### 3.3 Exposed API Keys

```typescript
// 💀 VULNERABLE — environment.ts
export const environment = {
  production: false,
  apiUrl: 'https://api.example.com',
  adminApiKey: 'sk_live_abc123def456',
  firebase: {
    apiKey: 'AIzaSyABC123...',
    authDomain: 'myapp.firebaseapp.com',
    databaseURL: 'https://myapp.firebaseio.com',
    projectId: 'myapp',
    storageBucket: 'myapp.appspot.com',
    messagingSenderId: '123456789',
    appId: '1:123456789:web:abc123'
  }
};
```

### 3.4 Route Guard Always Returns True

```typescript
// 💀 VULNERABLE
@Injectable({ providedIn: 'root' })
export class AdminGuard implements CanActivate {
  constructor(private auth: AuthService) {}

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean | UrlTree> | Promise<boolean | UrlTree> | boolean | UrlTree {
    return true; // 💀 Always allows access — placeholder never replaced
  }
}
```

---

## 4. Secure Code Fix

### 4.1 Context-Aware DomSanitizer

```typescript
// ✅ SECURE — Use context-aware sanitization
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

export class SafePipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}

  transform(value: string, context: 'html' | 'url' | 'style' = 'html'): SafeHtml {
    // Still use with caution — only for trusted content
    // Prefer [innerText] or property binding when possible
    switch (context) {
      case 'html':
        return this.sanitizer.sanitize(SecurityContext.HTML, value) as SafeHtml;
      // Never use bypassSecurityTrust* with user input
      default:
        return this.sanitizer.sanitize(SecurityContext.HTML, value) as SafeHtml;
    }
  }
}

// ✅ PREFERRED — Use property binding instead of bypass
<!-- Instead of bypassSecurityTrustHtml, use safe binding -->
<div>{{ user.content }}</div>  <!-- Auto-escaped by Angular -->
```

### 4.2 HTTP Interceptor for Auth

```typescript
// ✅ SECURE — HTTP interceptor for auth headers
@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private auth: AuthService) {}

  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const token = this.auth.getToken();

    if (token) {
      const cloned = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
          'X-XSRF-TOKEN': this.auth.getXsrfToken()
        },
        withCredentials: true
      });
      return next.handle(cloned);
    }

    return next.handle(req);
  }
}

// Register in AppModule:
// providers: [{ provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true }]
```

### 4.3 Secrets — Use Backend Proxy Only

```typescript
// ✅ SECURE — environment.ts (public-safe only)
export const environment = {
  production: true,
  apiUrl: 'https://api.example.com',
  // NEVER put API keys, secrets, or tokens here
  // Use a backend BFF (Backend for Frontend) proxy
};

// ✅ SECURE — Everything secret goes through a backend proxy
// Angular calls:  GET /api/proxy/external-service
// Backend adds:   Authorization: Bearer sk_live_xxx
// Client never sees the API key
```

### 4.4 Proper Route Guards

```typescript
// ✅ SECURE — Functional route guard (Angular 15+)
export const adminGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot,
  state: RouterStateSnapshot
): Observable<boolean | UrlTree> => {
  const auth = inject(AuthService);
  const router = inject(Router);

  return auth.isAuthenticated$.pipe(
    take(1),
    map(isAuthenticated => {
      if (!isAuthenticated) {
        return router.parseUrl('/login');
      }
      const userRole = auth.currentUserRole();
      if (userRole !== 'admin') {
        return router.parseUrl('/unauthorized');
      }
      return true;
    })
  );
};

// ✅ Apply to both route and children
const routes: Routes = [
  {
    path: 'admin',
    canActivate: [adminGuard],
    canActivateChild: [adminGuard],
    children: [
      { path: 'users', component: UsersComponent },
      { path: 'settings', component: SettingsComponent }
    ]
  }
];
```

---

## 5. Real CVEs (Verified via NVD)

### CVE-2026-27739 — SSRF in Angular SSR
- **Published:** 2026-02-25
- **CVSS:** Not yet assigned (NVD analysis pending)
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Affected:** Angular SSR `@angular/ssr` prior to 21.2.0-rc.1, 21.1.5, 20.3.17, 19.2.21
- **Description:** The Angular SSR request handling pipeline does not properly validate internally reconstructed URLs. An attacker can craft a request that triggers Angular's internal URL reconstruction to point to an arbitrary host, enabling SSRF. This allows accessing internal cloud metadata endpoints (e.g., `http://169.254.169.254/`), internal services, and otherwise protected infrastructure.
- **Fix:** Upgrade to `@angular/ssr` >= 21.2.0-rc.1, 21.1.5, 20.3.17, or 19.2.21. Server-side URL reconstruction now validates against the application's allowed origins.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-27739

### CVE-2026-54264 — Information Disclosure in Angular Service Worker
- **Published:** 2026-06-22
- **CVSS:** Not yet assigned (NVD analysis pending)
- **CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Affected:** `@angular/service-worker` prior to 22.0.1, 21.2.17, 20.3.25
- **Description:** When the Angular Service Worker fetches assets, it preserves metadata (such as headers) from the original request. An attacker who can observe cached responses or exploit a Service Worker scope mismatch may be able to infer sensitive response headers or cached data.
- **Fix:** Upgrade to `@angular/service-worker` >= 22.0.1, 21.2.17, or 20.3.25. The Service Worker now sanitizes response metadata before caching.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-54264

### CVE-2026-54268 — Denial of Service in Angular DatePipe
- **Published:** 2026-06-22
- **CVSS:** Not yet assigned (NVD analysis pending)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Affected:** `@angular/common` prior to 22.0.1, 21.2.17, 20.3.25
- **Description:** The `formatDate` function (and the standard Angular DatePipe) does not properly limit or validate the length of format strings. An attacker can provide an extremely long or deeply nested format pattern that causes the date formatter to consume excessive CPU and memory, leading to application-level denial of service.
- **Fix:** Upgrade to Angular >= 22.0.1, 21.2.17, or 20.3.25. Format strings are now length-limited and pattern-validated.
- **NVD Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-54268

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

## References

- Angular Security Guide: https://angular.io/guide/security
- Angular Cheatsheet — Security: https://angular.io/guide/security-cheatsheet
- Angular GitHub Security Advisories: https://github.com/angular/angular/security/advisories
- NVD Angular CVEs: https://nvd.nist.gov/vuln/search/results?query=angular&search_type=all
- CVE-2026-27739 Details: https://nvd.nist.gov/vuln/detail/CVE-2026-27739
- CVE-2026-54264 Details: https://nvd.nist.gov/vuln/detail/CVE-2026-54264
- CVE-2026-54268 Details: https://nvd.nist.gov/vuln/detail/CVE-2026-54268
- PortSwigger Angular Security Research: https://portswigger.net/web-security/cross-site-scripting/angular
- OWASP XSS Prevention Cheatsheet (Angular): https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#angular-2-and-above
