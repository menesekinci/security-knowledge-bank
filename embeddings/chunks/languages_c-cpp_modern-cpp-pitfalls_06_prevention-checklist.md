---
source: "languages/c-cpp/modern-cpp-pitfalls.md"
title: "Modern C++ Pitfalls (AI-Generated)"
heading: "Prevention Checklist"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] No raw owning pointers in new code (`new`/`delete` banned)
- [ ] clang-tidy checks enabled: `cppcoreguidelines-*`, `misc-lifetime`, `bugprone-*`
- [ ] ASan/TSan/LSan in CI for every build
- [ ] Review all `string_view` returns — verify they outlive their backing storage
- [ ] Review all lambda captures: prefer `[=]` (C++14 generalized capture) or explicit `[data = std::move(x)]` over `[&]`
- [ ] Never `detach()` threads with reference captures — always `join()` or use `std::jthread`
- [ ] Coroutines: ensure all captured references live at least as long as the coroutine handle
- [ ] Enable `-Wunused`, `-Wdangling-reference`, `-Wnoexcept` and treat as errors
- [ ] Use `std::make_unique` / `std::make_shared` — never `new`/`delete` directly
- [ ] Check for `shared_ptr` cycles with LSan or dedicated cycle-detection tooling
- [ ] `std::optional` / `std::any` — always check `.has_value()` before access

---