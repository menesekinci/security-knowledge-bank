---
source: "languages/typescript/reflect-metadata.md"
title: "Reflection & Metadata Injection — TypeScript"
heading: "Prevention Checklist"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, coding, explanation, language-vuln, prevention, secure, typescript, vibe, vulnerability]
chunk: 5/6
---

## Prevention Checklist

- [ ] Never expose reflection metadata through API endpoints
- [ ] Always validate runtime data against schemas (Zod, Yup) regardless of metadata
- [ ] Do NOT rely on Symbol keys to hide metadata — `getMetadataKeys()` returns Symbol keys too; keep secrets out of metadata entirely
- [ ] Prefer constructor injection over property/reflection injection
- [ ] Be aware that `design:type`, `design:paramtypes`, `design:returntype` are NOT security mechanisms
- [ ] Sanitize any values before storing via `Reflect.defineMetadata`

---