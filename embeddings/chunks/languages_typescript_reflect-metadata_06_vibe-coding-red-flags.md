---
source: "languages/typescript/reflect-metadata.md"
title: "Reflection & Metadata Injection — TypeScript"
heading: "Vibe Coding Red Flags"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, coding, explanation, language-vuln, prevention, secure, typescript, vibe, vulnerability]
chunk: 6/6
---

## Vibe Coding Red Flags

In AI-generated TypeScript, flag these:

```typescript
Reflect.getMetadata('design:type', ...)     // ⚠️ Type disclosure risk
Reflect.defineMetadata(key, userInput, ...)  // ⚠️ Metadata injection
Reflect.getMetadataKeys(target)              // ⚠️ Enumeration risk
```

> **Golden Rule:** `reflect-metadata` stores type information at runtime, but that information is only as trustworthy as the code that defined it. Never rely on metadata for security decisions.