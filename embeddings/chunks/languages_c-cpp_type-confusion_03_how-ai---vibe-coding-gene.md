---
source: "languages/c-cpp/type-confusion.md"
title: "Type Confusion (C/C++)"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

```cpp
Base *b = factory();
auto *d = static_cast<Derived*>(b); // AI assumes type without check
d->special();
```

Or C:

```c
void *p = read_msg();
struct Admin *a = p; // no tag check
```

AI models frequently generate these patterns because they mimic "just make it compile" fixes seen in forums. A common chain is:

1. AI writes generic factory code returning `Base*`
2. Developer needs to access a derived-specific method
3. AI suggests `static_cast` as the "simplest fix"
4. No runtime type verification is added

---