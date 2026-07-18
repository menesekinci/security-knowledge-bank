---
source: "languages/javascript/angular-security.md"
title: "Angular Security Deep Dive"
heading: "3. Vulnerable Code Examples"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [code, explanation, javascript, language-vuln, overview, secure, vulnerability, vulnerable]
chunk: 5/10
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