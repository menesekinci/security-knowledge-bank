---
source: "languages/typescript/decorator-abuse.md"
title: "Decorator Abuse — TypeScript"
heading: "Secure Code Fix"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, coding, explanation, language-vuln, prevention, secure, typescript, vibe, vulnerability]
chunk: 4/6
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