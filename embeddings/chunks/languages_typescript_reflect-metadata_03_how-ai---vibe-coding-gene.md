---
source: "languages/typescript/reflect-metadata.md"
title: "Reflection & Metadata Injection — TypeScript"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, coding, explanation, language-vuln, prevention, secure, typescript, vibe, vulnerability]
chunk: 3/6
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