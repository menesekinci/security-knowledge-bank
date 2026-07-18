---
source: "languages/javascript/angular-security.md"
title: "Angular Security Deep Dive"
heading: "4. Secure Code Fix"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 6/10
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