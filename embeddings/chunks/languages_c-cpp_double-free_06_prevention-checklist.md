---
source: "languages/c-cpp/double-free.md"
title: "Double-Free Memory Corruption (C/C++)"
heading: "Prevention Checklist"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] Document ownership for every heap pointer (who allocates, who frees)
- [ ] One teardown function per object; never free fields ad hoc across layers
- [ ] No raw `new`/`delete` in modern C++ application code without justification
- [ ] Implement Rule of 0/3/5 correctly; delete copy ops if ownership is unique
- [ ] ASan/MSan in CI for all native tests; run under release-like allocators too
- [ ] Review all `goto fail` / multi-exit functions for paired free paths
- [ ] FFI boundaries: agree which side frees; never free twice across languages
- [ ] Refcount APIs: atomic ops, overflow checks, clear transfer-of-ownership calls
- [ ] Ban custom dual free in “defensive” code reviews — second free is not safety
- [ ] Fuzz parsers and loaders that allocate trees of objects

---