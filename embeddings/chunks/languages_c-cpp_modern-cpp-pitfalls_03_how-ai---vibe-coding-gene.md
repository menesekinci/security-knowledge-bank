---
source: "languages/c-cpp/modern-cpp-pitfalls.md"
title: "Modern C++ Pitfalls (AI-Generated)"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

```cpp
std::string_view sv = std::string("temp"); // dangling
std::thread t([&]{ use(local); }); // ref to stack
t.detach();
```

Common AI-generated patterns:

1. **"Just make it work" string_view:** Model sees a string function and substitutes `string_view` for efficiency but misses the lifetime implication
2. **Detached thread with capture:** Model copies a threading example, uses `[&]` for convenience, then calls `detach()` so it "doesn't block"
3. **`shared_ptr` for everything:** Model overuses `shared_ptr` to avoid thinking about ownership — causes cycle leaks
4. **Coroutine from sync function:** Model wraps blocking code in a coroutine but doesn't understand the frame lifetime

---