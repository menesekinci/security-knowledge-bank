---
source: "languages/c-cpp/uninitialized-memory.md"
title: "Uninitialized Memory Use (C/C++)"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

- Uses `malloc(sizeof(T))` then sets only some fields; remaining fields/padding leak via `write`/`send`/`memcpy` of whole struct.
- Declares `int auth;` and only sets it on success path; failure path reads it.
- Ports Java/Go mental model (“fields default to zero”) into C.
- “Optimized” crypto examples that skip wiping or skip initializing IV/nonce buffers (sometimes also confuses uninit with lack of random — see insecure-random.md).
- Partial `memcpy` into buffers then treats full buffer as defined.
- C++: default constructors that leave members uninitialized; AI-generated structs without constructors.
- Kernel-style `copy_to_user` of stack structs without `memset` first — AI copies driver snippets incorrectly.
- Mixing `operator new` with C APIs that expect zeroed memory.

---