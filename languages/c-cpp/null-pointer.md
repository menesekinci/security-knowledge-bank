# 🟠 C/C++ Null Pointer Dereference

### What Is It?
`malloc()` and `calloc()` return `NULL` when they fail. Plain C++ `new` does **NOT** return `NULL` — it throws `std::bad_alloc`; only `new (std::nothrow)` returns `NULL` on failure. If the AI dereferences a `NULL` (from `malloc`/`calloc`/`nothrow new`) without checking, writing to that null pointer → crash or exploit.

## Example
```c
// 💀 VULNERABLE:
char* buf = (char*)malloc(1024);
strcpy(buf, "hello");  // if malloc fails → buf == NULL → crash!

// ✅ SECURE:
char* buf = (char*)malloc(1024);
if (buf == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    return -1;
}
strcpy(buf, "hello");
```

## Prevention
- A NULL check after every `malloc`/`calloc`/`new`
- If you use `nothrow new`, check as well
- Modern C++: `std::make_unique`, `std::make_shared` (throw exceptions)

---

**Severity: 🟠 High** — Crash, potential DoS.
**CWE: CWE-476**
