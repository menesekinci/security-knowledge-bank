---
source: "languages/c-cpp/modern-cpp-pitfalls.md"
title: "Modern C++ Pitfalls (AI-Generated)"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example

### 1. String_view dangle

```cpp
std::string_view get_env(const char* key) {
    std::string val = std::getenv(key) ? std::getenv(key) : "";
    return val; // BUG: val destroyed, string_view dangles
}
```

### 2. Lambda capture + async (common in AI-generated code)

```cpp
// AI-generated async task with dangling capture
void start_worker() {
    std::vector<int> data = load_data();
    std::thread([&] {             // BUG: captures data by reference
        for (int x : data) { ... } // data may be destroyed before thread runs
    }).detach();
    // data destroyed at end of start_worker, thread continues
}
```

### 3. Shared_ptr cycle

```cpp
struct Node {
    std::shared_ptr<Node> next; // BUG: cycle in circular list
};

auto a = std::make_shared<Node>();
auto b = std::make_shared<Node>();
a->next = b;
b->next = a; // cycle — never freed
```

### 4. Coroutine stack capture

```cpp
// AI-generated task framework — lifetime bug
Task<void> process_async(Database& db) {
    auto results = db.query("SELECT *"); // temporary
    co_await db.execute(results);        // BUG: results may be destroyed
}
```

---