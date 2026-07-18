---
source: "languages/c-cpp/modern-cpp-pitfalls.md"
title: "Modern C++ Pitfalls (AI-Generated)"
heading: "Vibe-Coding Red Flags"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe-Coding Red Flags

- `new` / `delete` without matching smart pointer — especially in any code claiming "modern C++"
- `string_view` stored as a class member (almost always a lifetime bomb)
- `detach()` on threads with `[&]` capture — the classic AI-generated async disaster
- Copy-paste C APIs into C++ without RAII wrappers (raw `FILE*`, `malloc`/`free`, `new[]`/`delete[]`)
- `std::move` applied to `const` objects or function return values ("move pessimization")
- `co_await` inside a loop with captured stack variables — coroutine frame lifetime issues
- `std::generator` yielding references to local variables in the generator function
- `std::span` constructed from a temporary `std::vector` or `std::string`
- `shared_ptr` cycles without a single `weak_ptr` to break them
- `noexcept` on functions that call `std::vector::push_back` or other potentially-throwing operations
- `reinterpret_cast` to convert between pointer types "because the compiler complained"
- `std::bind` or `std::function` with `std::ref` to local variables
- Non-owning raw pointers returned from factory functions that should return `unique_ptr`
- `std::optional<T&>` — this is illegal in C++ (optional references are not allowed) but AI sometimes generates it