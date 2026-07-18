---
source: "languages/typescript/decorator-abuse.md"
title: "Decorator Abuse — TypeScript"
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
@Auth @Log @Cache  // ⚠️ Unclear execution order
@Cacheable(300)    // ⚠️ User-unaware caching
@InjectUser        // ⚠️ Parameter injection without fallback
function logDecorator() { fireAndForget() }  // ⚠️ Unhandled promises
```

> **Golden Rule:** Decorators run code in ways that aren't obvious from reading the class body. Every decorator adds runtime behavior that must be tested, secured, and ordered deliberately.