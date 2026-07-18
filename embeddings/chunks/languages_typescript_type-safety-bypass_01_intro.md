---
source: "languages/typescript/type-safety-bypass.md"
title: "🟡 TypeScript Type Safety Bypass"
heading: "intro"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 1/8
---

# 🟡 TypeScript Type Safety Bypass

> **Severity:** 🟡 Medium–High
> **CWE:** CWE-704 (Incorrect Type Conversion), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), CWE-843 (Type Confusion)
> **AI Generation Risk:** Very High — LLMs frequently emit `as any`, `@ts-ignore`, and unchecked casts to silence the compiler

---