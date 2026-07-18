---
source: "languages/c-cpp/type-confusion.md"
title: "Type Confusion (C/C++)"
heading: "Prevention Checklist"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] No `reinterpret_cast` without threat review
- [ ] Tagged messages + length checks before dispatch
- [ ] Fuzzing with ASan/UBSan is mandatory for parsers
- [ ] Avoid polymorphic downcasts without `dynamic_cast` or `typeid` checks
- [ ] Default/else case in all type switches — reject unknown tags
- [ ] Prefer `std::variant` over manual type tagging
- [ ] Validate buffer sizes before casting — type confusion + buffer overflow = RCE
- [ ] In kernel code, validate all `IOCTL` parameters before interpreting type
- [ ] Use `-Wstrict-aliasing` and enable it as error
- [ ] JIT engine code: never trust object maps or inline caches from untrusted input

---