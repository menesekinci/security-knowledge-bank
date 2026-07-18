---
source: "languages/c-cpp/double-free.md"
title: "Double-Free Memory Corruption (C/C++)"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

AI-generated C/C++ is especially prone to double-free because models optimize for “every path cleans up” without a single ownership story:

- **Duplicate cleanup:** `free(buf)` in a `fail:` label **and** at the end of the function after `goto fail`.
- **Defensive free everywhere:** “free if non-null” copied into multiple helpers that all run.
- **Mixed styles:** partial migration to smart pointers while still calling `delete` manually.
- **Error samples from blogs:** teaching code that frees on error then returns a freed pointer to the caller who also frees.
- **CGo / JNI / N-API bridges:** free on both sides of the FFI boundary.
- **Refactor residue:** AI extracts a `release_resource()` and also leaves the original `free` in place.
- **Arrays vs scalars:** `new[]` paired with `delete` (undefined behavior; may interact with heap in double-free-like ways) — models mix these constantly.

Prompts like “add proper error handling and free all memory” without specifying **who owns what** reliably produce double-frees.

---