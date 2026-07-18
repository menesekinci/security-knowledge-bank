# Reflection & Metadata Injection — TypeScript

> **Severity:** Medium–High
> **CVSS:** 5.3–7.5
> **AI Generation Risk:** Medium — AI models use `reflect-metadata` for dependency injection and serialization

---

## Vulnerability Explanation

`reflect-metadata` is a polyfill for the [Reflect Metadata](https://rbuckton.github.io/reflect-metadata/) proposal that allows attaching metadata to class declarations and property definitions at runtime. While powerful for decorator-based frameworks (Angular, NestJS, TypeORM), it introduces security concerns:

1. **Metadata injection** — Attackers can manipulate metadata stored on prototypes if they can influence runtime behavior
2. **Type confusion via reflection** — Metadata types are strings, not checked at runtime
3. **Information disclosure** — Metadata can leak internal design types to attackers
4. **Deserialization abuse** — `Reflect.getMetadata('design:type', ...)` reveals TypeScript types at runtime

### How Reflect Metadata Works

```typescript
import 'reflect-metadata';

class User {
  @Expose()
  name: string;
}

// Types are stored as metadata at runtime:
console.log(Reflect.getMetadata('design:type', User.prototype, 'name'));
// → [Function: String] — Reveals the TypeScript type at runtime!
```

---

## How AI / Vibe Coding Generates This

### 1. Over-reliance on Reflection for Validation

```typescript
// 🚫 VULNERABLE — AI using reflection for "type safety"
import 'reflect-metadata';

function validate(obj: any): boolean {
  const type = Reflect.getMetadata('design:type', obj, 'property');
  // AI assumes the metadata type matches runtime data
  return type === String;  // 💥 Metadata can be manipulated!
}
```

### 2. Exposing Internal Types via API

```typescript
// 🚫 VULNERABLE — AI-generated API that leaks types
app.get('/schema/:entity', (req, res) => {
  const EntityClass = getEntityClass(req.params.entity);
  const properties = Reflect.getMetadataKeys(EntityClass.prototype);
  
  // AI exposes metadata via API — information disclosure
  const schema = properties.map(prop => ({
    name: prop,
    type: Reflect.getMetadata('design:type', EntityClass.prototype, prop)?.name,
    // 💥 Reveals: String, Number, User, Admin — internal type info
  }));
  
  res.json(schema);
  // Attacker learns internal class structure for further attacks
});
```

### 3. Reflection-Based Deserialization

```typescript
// 🚫 VULNERABLE — AI-generated generic deserializer
function deserialize(data: any, targetType: new () => any): any {
  const instance = new targetType();
  
  // AI uses reflection to automatically populate fields
  for (const key of Object.keys(data)) {
    const type = Reflect.getMetadata('design:type', targetType.prototype, key);
    
    if (type === Number) {
      instance[key] = Number(data[key]);  // 💥 NaN injection
    } else if (type === Boolean) {
      instance[key] = Boolean(data[key]);  // 💥 Always true for non-empty strings
    } else {
      instance[key] = data[key];  // 💥 Unvalidated assignment
    }
  }
  
  return instance;
}
```

### 4. NestJS-style Parameter Injection

```typescript
// 🚫 VULNERABLE — Reflection-based DI with untrusted identifiers
function Inject(serviceName?: string) {
  return function(target: any, key: string) {
    // AI stores service name in metadata
    Reflect.defineMetadata('inject:service', serviceName || key, target, key);
  };
}

class PaymentService {
  @Inject('PaymentGateway')  // If this string comes from config, it's injectable
  private gateway: any;
}
```

---

## Secure Code Fix

### Fix 1: Validate Metadata at Runtime

```typescript
// ✅ SAFE — Validate runtime data regardless of metadata
import 'reflect-metadata';
import { z } from 'zod';

const VALIDATION_MAP = new Map<Function, z.ZodSchema>([
  [String, z.string()],
  [Number, z.number()],
  [Boolean, z.boolean()],
  [Date, z.string().datetime().pipe(z.coerce.date())],
]);

function safeDeserialize(data: any, targetType: new () => any): any {
  const instance = new targetType();
  
  for (const key of Object.keys(data)) {
    const designType = Reflect.getMetadata('design:type', targetType.prototype, key);
    const validator = VALIDATION_MAP.get(designType);
    
    if (validator) {
      try {
        instance[key] = validator.parse(data[key]);
      } catch {
        throw new Error(`Invalid value for ${key}: expected ${designType?.name}`);
      }
    } else {
      // For complex types, use a more specific validator
      instance[key] = data[key];  // Still risky — validate complex types
    }
  }
  
  return instance;
}
```

### Fix 2: Don't Expose Reflection Metadata via API

```typescript
// ✅ SAFE — Never expose internal type metadata to clients
app.get('/schema/:entity', (req, res) => {
  const EntityClass = getEntityClass(req.params.entity);
  
  // Instead of reflecting types, define a safe API schema
  const safeSchema = defineApiSchema(EntityClass);
  res.json(safeSchema);
  // ✅ Only exposes: {name: "string", email: "string"} — not internal types
});

function defineApiSchema(cls: new () => any): Record<string, string> {
  // Always use a predefined mapping, never reflection
  return {
    name: 'string',
    email: 'string',
  };
}
```

### Fix 3: Don't Treat Metadata Keys as a Secrecy Mechanism

```typescript
// ⚠️ MYTH — Symbol keys are NOT hidden from reflection.
// Reflect.getMetadataKeys() returns ALL keys, including Symbol keys.
const INJECTION_KEY = Symbol('injection:service');

function Inject(serviceName: string) {
  return function(target: any, key: string) {
    Reflect.defineMetadata(INJECTION_KEY, serviceName, target, key);
  };
}

const keys = Reflect.getMetadataKeys(target);
// keys DOES include INJECTION_KEY — Symbols are enumerable via reflection.
// Anyone with a reference to the class can read the value too:
Reflect.getMetadata(INJECTION_KEY, target);  // returns the service name

// ✅ SAFE — Symbol keys only prevent *accidental* string-key collisions.
// For real confidentiality, keep secrets OUT of metadata entirely.
// Store security-sensitive data in a closure or a private WeakMap that is
// never handed to reflection at all:
const injectionRegistry = new WeakMap<object, string>();

function SecureInject(serviceName: string) {
  return function(target: any, _key: string) {
    // Not reachable via Reflect.getMetadataKeys / getMetadata
    injectionRegistry.set(target, serviceName);
  };
}
```

> **Why:** `Reflect.getMetadataKeys()` (and `getOwnMetadataKeys()`) enumerate string
> **and** Symbol keys. Using a `Symbol` avoids name clashes with other libraries, but it
> is **not** an access-control boundary. If metadata must stay secret, don't store it as
> metadata.

### Fix 4: Use Plain DI Instead of Reflection-Based DI

```typescript
// ✅ SAFE — Explicit dependency injection
class PaymentService {
  constructor(
    private readonly gateway: PaymentGateway,  // ✅ Explicit, type-checked
    private readonly logger: Logger
  ) {}
}

// Manual wiring — no reflection, no injection metadata
const gateway = new StripeGateway(config.stripeKey);
const logger = new ConsoleLogger();
const paymentService = new PaymentService(gateway, logger);
```

---

## Prevention Checklist

- [ ] Never expose reflection metadata through API endpoints
- [ ] Always validate runtime data against schemas (Zod, Yup) regardless of metadata
- [ ] Do NOT rely on Symbol keys to hide metadata — `getMetadataKeys()` returns Symbol keys too; keep secrets out of metadata entirely
- [ ] Prefer constructor injection over property/reflection injection
- [ ] Be aware that `design:type`, `design:paramtypes`, `design:returntype` are NOT security mechanisms
- [ ] Sanitize any values before storing via `Reflect.defineMetadata`

---

## Vibe Coding Red Flags

In AI-generated TypeScript, flag these:

```typescript
Reflect.getMetadata('design:type', ...)     // ⚠️ Type disclosure risk
Reflect.defineMetadata(key, userInput, ...)  // ⚠️ Metadata injection
Reflect.getMetadataKeys(target)              // ⚠️ Enumeration risk
```

> **Golden Rule:** `reflect-metadata` stores type information at runtime, but that information is only as trustworthy as the code that defined it. Never rely on metadata for security decisions.
