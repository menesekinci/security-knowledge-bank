---
source: "languages/typescript/reflect-metadata.md"
title: "Reflection & Metadata Injection — TypeScript"
heading: "Secure Code Fix"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, coding, explanation, language-vuln, prevention, secure, typescript, vibe, vulnerability]
chunk: 4/6
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