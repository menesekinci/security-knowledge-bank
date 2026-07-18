---
source: "languages/c-cpp/double-free.md"
title: "Double-Free Memory Corruption (C/C++)"
heading: "Secure Code Fix"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 5/8
---

## Secure Code Fix

### C — single owner, free once, NULL out

```c
void record_destroy(Record *r) {
    if (!r) return;
    free(r->name);
    r->name = NULL;
    free(r->data);
    r->data = NULL;
    free(r);
}

int load_record(const char *path, Record **out) {
    Record *r = record_create("default", 1024);
    if (!r) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) {
        record_destroy(r);  /* only once */
        return -1;
    }

    size_t got = fread(r->data, 1, 1024, f);
    fclose(f);
    if (got < 1) {
        record_destroy(r);
        return -1;
    }

    *out = r;
    return 0;
}
```

### C++ — rule of five / unique ownership

```cpp
#include <memory>
#include <vector>

class Buffer {
public:
    explicit Buffer(size_t n) : data_(n) {}
    // vector manages memory; default copy/move are safe (deep/move as defined)

    char* data() { return data_.data(); }
    size_t size() const { return data_.size(); }

private:
    std::vector<char> data_;
};

// Or exclusive ownership:
std::unique_ptr<char[]> make_buf(size_t n) {
    return std::make_unique<char[]>(n);
}
```

### Hardening

- Compile with **AddressSanitizer** (`-fsanitize=address`) in CI and tests.
- Prefer `std::unique_ptr` / `std::shared_ptr` (with clear sharing rationale) over raw `new`/`delete`.
- In C, encapsulate free in one function; set pointers to `NULL` after free if aliases may remain (not a complete fix alone, but helps accidental second free of the same variable).
- Static analyzers: clang-tidy, Coverity, CodeQL `cpp/double-free`.

---