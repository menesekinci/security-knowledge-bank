# Decorator Abuse — TypeScript

> **Severity:** Medium
> **CVSS:** 5.3–6.5
> **AI Generation Risk:** High — AI models overuse decorators for cross-cutting concerns without understanding their security implications

---

## Vulnerability Explanation

TypeScript decorators are functions that run at class definition time, modifying constructors, methods, properties, or parameters. While powerful for cross-cutting concerns (logging, auth, caching), they introduce security risks because:

1. **Decorators run during module import** — before your app is fully initialized
2. **Decorator order matters** — the wrong order can skip authentication
3. **Decorator errors can bypass security** — an exception in a decorator may leave the decorated method in an undefined state
4. **Reflection + decorators create new injection surfaces**

### How Decorators Execute

```typescript
function Auth(target: any, key: string, descriptor: PropertyDescriptor) {
  const original = descriptor.value;
  descriptor.value = function(...args: any[]) {
    // Decorator runs EVERY TIME the method is called
    if (!this.user?.isAdmin) {
      throw new Error('Unauthorized');
    }
    return original.apply(this, args);
  };
}

class AdminController {
  @Auth
  deleteUser(id: string) { ... }
}
```

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

## Secure Code Fix

### Fix 1: Robust Auth Decorator

```typescript
// ✅ SAFE — Auth decorator with proper null checks
function AdminOnly(): MethodDecorator {
  return function(target: any, key: string, descriptor: PropertyDescriptor) {
    const original = descriptor.value;
    
    descriptor.value = function(this: any, ...args: any[]) {
      // ✅ Defensive null check
      if (!this.user || this.user.role !== 'admin') {
        throw new Error('Unauthorized: admin role required');
      }
      
      try {
        return original.apply(this, args);
      } catch (err) {
        // Log and re-throw — don't swallow errors
        console.error(`Error in ${key}:`, err);
        throw err;
      }
    };
    
    return descriptor;
  };
}
```

### Fix 2: User-Specific Caching

```typescript
// ✅ SAFE — Cache includes user context
function UserSpecificCache(ttl: number = 300): MethodDecorator {
  return function(target: any, key: string, descriptor: PropertyDescriptor) {
    const original = descriptor.value;
    const cache = new Map<string, { data: any; expiry: number }>();
    
    descriptor.value = function(this: any, ...args: any[]) {
      // ✅ Include user ID in cache key
      const userId = this.req?.user?.id || 'anonymous';
      const cacheKey = `${userId}:${JSON.stringify(args)}`;
      
      const cached = cache.get(cacheKey);
      if (cached && cached.expiry > Date.now()) {
        return cached.data;
      }
      
      const result = original.apply(this, args);
      cache.set(cacheKey, { data: result, expiry: Date.now() + ttl * 1000 });
      return result;
    };
  };
}
```

### Fix 3: Decorator Order Validation

```typescript
// ✅ SAFE — Put the gatekeeping security decorator at the TOP so it runs FIRST
class UserController {
  // Two different orders are at play — don't confuse them:
  //
  //  • APPLICATION (wrapping) happens bottom-up: the decorator CLOSEST to the
  //    method wraps the original first and becomes the INNERMOST wrapper.
  //  • EXECUTION (at call time) happens top-down: the OUTERMOST/TOP decorator's
  //    wrapper runs FIRST; the one CLOSEST to the method runs LAST, right before
  //    the method body. (Same mechanic as the section 4 example above.)
  //
  // So to make a security check run before anything else, place it at the TOP.

  @ValidateInput   // Runs 1st at call time (outermost) — reject bad input early
  @RateLimit       // Runs 2nd
  @Log             // Runs 3rd (innermost, closest to method), then createUser()
  createUser(data: CreateUserDto) { ... }

  // Call-time order: ValidateInput → RateLimit → Log → createUser()
}
```

### Fix 4: Proper Async Decorator with Error Handling

```typescript
// ✅ SAFE — Async-aware decorator
function AsyncAuditLog(): MethodDecorator {
  return function(target: any, key: string, descriptor: PropertyDescriptor) {
    const original = descriptor.value;
    
    descriptor.value = async function(this: any, ...args: any[]) {
      try {
        const result = await original.apply(this, args);
        await logAudit(key, args, 'success');  // ✅ Awaited
        return result;
      } catch (err) {
        await logAudit(key, args, 'error', err);  // ✅ Error logged
        throw err;  // ✅ Re-throw — don't swallow
      }
    };
  };
}
```

### Fix 5: Testing Decorators Directly

```typescript
// ✅ SAFE — Test decorator behavior directly
describe('AdminOnly decorator', () => {
  it('should throw when user is not admin', () => {
    const instance = new TestController();
    instance.user = { role: 'user' };
    
    expect(() => instance.sensitiveMethod()).toThrow('Unauthorized');
  });
  
  it('should allow admins', () => {
    const instance = new TestController();
    instance.user = { role: 'admin' };
    
    expect(() => instance.sensitiveMethod()).not.toThrow();
  });
});
```

---

## Prevention Checklist

- [ ] Test decorated methods with invalid/unauthenticated contexts
- [ ] Never use fire-and-forget patterns in decorators (await logging/auditing)
- [ ] Verify decorator order — the TOP (outermost) decorator runs FIRST at call time, so place the gatekeeping security decorator at the top
- [ ] Use explicit error handling in decorators — never catch without re-throwing
- [ ] Make caching decorators user-aware when caching user-specific data
- [ ] Don't modify parameters in parameter decorators (unexpected side effects)
- [ ] Document decorator execution order on classes with multiple decorators
- [ ] Test decorators as standalone units — not just through the full class

---

## Vibe Coding Red Flags

In AI-generated TypeScript, flag these:

```typescript
@Auth @Log @Cache  // ⚠️ Unclear execution order
@Cacheable(300)    // ⚠️ User-unaware caching
@InjectUser        // ⚠️ Parameter injection without fallback
function logDecorator() { fireAndForget() }  // ⚠️ Unhandled promises
```

> **Golden Rule:** Decorators run code in ways that aren't obvious from reading the class body. Every decorator adds runtime behavior that must be tested, secured, and ordered deliberately.
