---
source: "languages/c-cpp/type-confusion.md"
title: "Type Confusion (C/C++)"
heading: "Vibe-Coding Red Flags"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe-Coding Red Flags

- `static_cast<Derived*>(basePtr)` to "silence the compiler" without checking the real type
- `void*` soup in new C++ code — storing typed objects in untyped containers
- IPC structs without version/tag fields or magic numbers
- `reinterpret_cast` used to "treat bytes as a different struct"
- Raw union access where the discriminator is attacker-controllable
- Missing `default` case in switch dispatch — unhandled types pass through silently
- `memcpy` between unrelated struct types (type punning)
- AI-generated code that casts a buffer pointer to `struct foo*` without checking the buffer is large enough
- No `else` after `if (type == X)` — code that silently skips type validation