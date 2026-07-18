---
source: "languages/typescript/decorator-abuse.md"
title: "Decorator Abuse — TypeScript"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, coding, explanation, language-vuln, prevention, secure, typescript, vibe, vulnerability]
chunk: 3/6
---

## How AI / Vibe Coding Generates This

### 1. Auth Decorator with Broken Error Handling

```typescript
// 🚫 VULNERABLE — AI-generated auth decorator
function AdminOnly(target: any, key: string, descriptor: PropertyDescriptor) {
  const original = descriptor.value;
  
  descriptor.value = function(...args: any[]) {
    try {
      // AI assumes this.user exists — no null check
      if (this.user.role !== 'admin') {  // 💥 TypeError if this.user is undefined
        throw new Error('Forbidden');
      }
      return original.apply(this, args);
    } catch (e) {
      // 💥 If this.user is undefined, decorator throws BEFORE checking auth
      // The error is caught, but the original method might still execute!
    }
  };
}
```

### 2. Caching Decorator Leaking Sensitive Data

```typescript
// 🚫 VULNERABLE — AI-generated cache decorator
function Cacheable(ttl: number = 300) {
  return function(target: any, key: string, descriptor: PropertyDescriptor) {
    const original = descriptor.value;
    const cache = new Map<string, { data: any; expiry: number }>();
    
    descriptor.value = function(...args: any[]) {
      const cacheKey = JSON.stringify(args);
      const cached = cache.get(cacheKey);
      
      if (cached && cached.expiry > Date.now()) {
        return cached.data;  // 💥 Caches sensitive data across users!
        // User A's data is served to User B if same arguments
      }
      
      const result = original.apply(this, args);
      cache.set(cacheKey, { data: result, expiry: Date.now() + ttl * 1000 });
      return result;
    };
  };
}

class UserService {
  @Cacheable(60)
  async getUserProfile(userId: string) {
    // 💥 Cache key is just userId — but data varies by the requesting user's permissions
    return db.query('SELECT * FROM users WHERE id = ?', [userId]);
  }
}
```

### 3. Parameter Decorator Injection

```typescript
// 🚫 VULNERABLE — AI-generated parameter injection
function InjectUser(target: any, key: string, index: number) {
  // AI stores metadata to inject user at a parameter position
  Reflect.defineMetadata('inject:user', index, target, key);
}

class UserController {
  getProfile(@InjectUser user: User, id: string) {
    // AI assumes user is injected via middleware
    return user;  // 💥 If injection fails, user is undefined
  }
}
```

### 4. Decorator Order Leading to Auth Bypass

```typescript
// 🚫 VULNERABLE — AI-generated decorator ordering
class AdminPanel {
  @Log         // Runs first (bottom-up in TypeScript)
  @RateLimit   // Runs second
  @AdminOnly   // Runs last (closest to method)
  deleteAllUsers() { ... }
  
  // 💥 Execution order: Log → RateLimit → AdminOnly → deleteAllUsers
  // If Log throws, RateLimit and AdminOnly never execute — auth bypass!
}
```

### 5. Async Decorator Without Await

```typescript
// 🚫 VULNERABLE — AI-generated async decorator
function AuditLog(target: any, key: string, descriptor: PropertyDescriptor) {
  const original = descriptor.value;
  
  descriptor.value = function(...args: any[]) {
    logAudit(key, args);  // 💥 Fire-and-forget — exceptions swallowed
    return original.apply(this, args);  // Continues without awaiting log
  };
}
```

---