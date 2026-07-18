---
source: "languages/c-cpp/modern-cpp-pitfalls.md"
title: "Modern C++ Pitfalls (AI-Generated)"
heading: "Secure Code Fix"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 5/8
---

## Secure Code Fix

### Fix 1: String_view lifetime

```cpp
std::string get_env(const char* key) {
    const char* val = std::getenv(key);
    return val ? std::string(val) : std::string{};
}
// Or return std::string, not std::string_view, from factory functions
```

### Fix 2: Lambda captures — own by value for async

```cpp
void start_worker() {
    auto data = std::make_shared<std::vector<int>>(load_data());
    std::thread([data] { // capture shared_ptr by value — keeps data alive
        for (int x : *data) { ... }
    }).detach();
    // Safe: shared_ptr keeps data alive until thread finishes
}
```

Or better, join threads and avoid detach:

```cpp
void start_worker() {
    std::vector<int> data = load_data();
    std::thread t([data = std::move(data)] {
        for (int x : data) { ... }
    });
    t.join(); // or store thread handle and join later
}
```

### Fix 3: Weak_ptr breaks cycles

```cpp
struct Node {
    std::shared_ptr<Node> next;
    std::weak_ptr<Node> prev; // weak_ptr breaks the cycle
};

auto a = std::make_shared<Node>();
auto b = std::make_shared<Node>();
a->next = b;
b->prev = a; // safe: weak_ptr, not shared_ptr
```

### Fix 4: Coroutine lifetime — ensure captures survive

```cpp
Task<void> process_async(std::shared_ptr<Database> db, std::string query) {
    // Capture by value or shared_ptr
    auto results = co_await db->queryAsync(std::move(query));
    co_await db->executeAsync(std::move(results));
}
```

### General Safe Patterns

- `std::unique_ptr` by default; `shared_ptr` only for genuine shared ownership
- `std::weak_ptr` for cache/observer patterns
- Prefer `std::string` returns over `std::string_view` from non-trivial functions
- `std::span` only with proven lifetime — never store it, pass it down the call stack only
- Always `co_await` on values captured by copy in coroutines
- Use `std::move()` for ownership transfer into lambdas: `[data = std::move(vec)]`
- Enable lifetime analysis: clang-tidy, MSVC lifetime checker, GCC `-Wdangling-reference`

---