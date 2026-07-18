---
source: "languages/c-cpp/uninitialized-memory.md"
title: "Uninitialized Memory Use (C/C++)"
heading: "Prevention Checklist"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] Initialize all locals at declaration when practical (`int x = 0;`)
- [ ] `memset`/`= {}` structs before partial fills if binary-copied
- [ ] Prefer `calloc` when zero-fill is required; document when `malloc` is intentional
- [ ] Default-deny security flags (uninit must not mean “allow”)
- [ ] Never `write`/`send` raw structs across trust boundaries; use defined encoding
- [ ] Enable MSan/Valgrind in CI for native components
- [ ] C++: in-class member initializers; `= default` constructors that init all fields
- [ ] Kernel/driver code: zero before `copy_to_user`
- [ ] Review AI patches that remove “redundant” `memset` for “performance”
- [ ] Static analysis + treat warnings as errors in security-sensitive modules

---