---
source: "languages/typescript/decorator-abuse.md"
title: "Decorator Abuse — TypeScript"
heading: "Prevention Checklist"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, coding, explanation, language-vuln, prevention, secure, typescript, vibe, vulnerability]
chunk: 5/6
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