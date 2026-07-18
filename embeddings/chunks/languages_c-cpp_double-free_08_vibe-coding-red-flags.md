---
source: "languages/c-cpp/double-free.md"
title: "Double-Free Memory Corruption (C/C++)"
heading: "Vibe-Coding Red Flags"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe-Coding Red Flags

| AI pattern | Issue |
|------------|--------|
| `free(p); free(p);` “just to be sure” | Textbook double-free |
| `destroy(x); free(x);` | Destroy already freed the object |
| Shallow copy constructors with owned pointers | Double-delete on destruct |
| `shared_ptr` + manual `delete get()` | Breaks ownership |
| Cleanup in `catch` and again after `try` | Duplicate free on exception path |
| “Fixed leak” by adding `free` without removing other free | Leak → double-free swing |
| Returning pointer that callee and caller both free | Ownership confusion |
| No ASan in the same PR that touches alloc/free | Blind refactor |

**Review mantra:** *Every `malloc`/`new` has exactly one owning free/delete path — name that owner in the PR description.*

---

*KB level: L1 languages/c-cpp · CWE-415 · Pair with: use-after-free.md, buffer-overflow.md, memory-safety.md*