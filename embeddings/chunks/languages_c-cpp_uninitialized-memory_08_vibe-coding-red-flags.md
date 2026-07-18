---
source: "languages/c-cpp/uninitialized-memory.md"
title: "Uninitialized Memory Use (C/C++)"
heading: "Vibe-Coding Red Flags"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe-Coding Red Flags

| Pattern | Risk |
|---------|------|
| `malloc` + partial field init + `sizeof` send | Padding/field leak |
| `int flag;` without `= 0` on deny path | Auth bypass lottery |
| AI removes `memset` as “unnecessary” | Reintroduces leaks |
| Java-style assumption that fields are zero | Wrong for C stack |
| Logging “debug dumps” of raw structs | Operational secret leak |
| `new Foo` without `{}` or member init | Indeterminate members |
| No MSan in CI for crypto/auth code | Silent UB |
| Using uninitialized buffer as RNG entropy | Catastrophic crypto fail |

**Rule:** *If memory leaves the process (wire, disk, syscall), every byte must be intentionally defined.*

---

*KB level: L1 languages/c-cpp · CWE-457 · Pair with: buffer-overflow.md, insecure-random.md, memory-safety.md*