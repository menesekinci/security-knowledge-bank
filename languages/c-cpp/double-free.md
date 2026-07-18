# Double-Free Memory Corruption (C/C++)

> **Severity:** Critical (often leads to RCE or privilege escalation via heap corruption)  
> **CWE:** CWE-415 (Double Free), related CWE-416 (Use After Free), CWE-825 (Expired Pointer Dereference)  
> **AI Generation Risk:** High — AI frequently inserts redundant `free`/`delete` in error paths, cleanup helpers, and “defensive” duplicate teardown without ownership discipline

---

## Vulnerability Explanation

A **double-free** occurs when the same memory allocation is passed to a deallocator (`free`, `delete`, `delete[]`, custom arena free) more than once without an intervening reallocation that legitimately reuses that address under a new ownership cycle.

Consequences on typical heap allocators (ptmalloc, jemalloc, Windows heap, etc.):

1. **Heap metadata corruption** — free-list pointers, size fields, or tcache/fastbin structures are updated twice inconsistently.
2. **Arbitrary write primitives** — sophisticated exploitation can turn corruption into write-what-where (not detailed here).
3. **Immediate abort** — hardened allocators may detect and abort (`free(): double free detected`, AddressSanitizer reports).
4. **Use-after-free adjacency** — after the first free, another allocation may receive the same address; a second free then corrupts a live object.

Double-free is a **memory ownership** bug: two code paths both believe they own the same pointer. Classic triggers:

- Error-handling paths that free and then fall through to a normal cleanup that frees again.
- Struct fields freed in a destructor while a manual `cleanup()` also frees them.
- `realloc` failure handling that frees the old pointer incorrectly (or double-frees on success path mistakes).
- Aliased pointers: `p2 = p1; free(p1); free(p2);`
- Custom refcounting with off-by-one or missing atomic ops (free when count hits 0 twice).

C++ adds `delete` vs `delete[]` mismatches and double-`delete` on the same object when raw pointers are copied without clear ownership (`std::unique_ptr` exists precisely to prevent this).

---

## How AI / Vibe Coding Generates This

AI-generated C/C++ is especially prone to double-free because models optimize for “every path cleans up” without a single ownership story:

- **Duplicate cleanup:** `free(buf)` in a `fail:` label **and** at the end of the function after `goto fail`.
- **Defensive free everywhere:** “free if non-null” copied into multiple helpers that all run.
- **Mixed styles:** partial migration to smart pointers while still calling `delete` manually.
- **Error samples from blogs:** teaching code that frees on error then returns a freed pointer to the caller who also frees.
- **CGo / JNI / N-API bridges:** free on both sides of the FFI boundary.
- **Refactor residue:** AI extracts a `release_resource()` and also leaves the original `free` in place.
- **Arrays vs scalars:** `new[]` paired with `delete` (undefined behavior; may interact with heap in double-free-like ways) — models mix these constantly.

Prompts like “add proper error handling and free all memory” without specifying **who owns what** reliably produce double-frees.

---

## Vulnerable Code Example (realistic)

### C — error path double-free

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    char *name;
    char *data;
} Record;

Record *record_create(const char *name, size_t n) {
    Record *r = malloc(sizeof(Record));
    if (!r) return NULL;

    r->name = strdup(name);
    if (!r->name) {
        free(r);
        return NULL;
    }

    r->data = malloc(n);
    if (!r->data) {
        free(r->name);
        free(r);
        return NULL;
    }
    memset(r->data, 0, n);
    return r;
}

void record_destroy(Record *r) {
    if (!r) return;
    free(r->name);
    free(r->data);
    free(r);
}

/* 🔴 AI-style "safe" loader with overzealous cleanup */
int load_record(const char *path, Record **out) {
    Record *r = record_create("default", 1024);
    if (!r) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) {
        record_destroy(r);
        free(r);          /* 🔴 DOUBLE-FREE: destroy already freed r */
        return -1;
    }

    /* ... read into r->data ... */
    if (fread(r->data, 1, 1024, f) < 1) {
        fclose(f);
        free(r->data);    /* 🔴 partial free */
        record_destroy(r);/* 🔴 frees name + data + r again */
        return -1;
    }

    fclose(f);
    *out = r;
    return 0;
}
```

### C++ — raw pointer double-delete

```cpp
#include <cstring>

class Buffer {
public:
    explicit Buffer(size_t n) : data_(new char[n]), n_(n) {}
    ~Buffer() { delete[] data_; }

    // 🔴 AI-generated copy ctor: shallow copy
    Buffer(const Buffer& o) : data_(o.data_), n_(o.n_) {}
    // Both objects delete[] the same pointer on destruction → double-free

private:
    char* data_;
    size_t n_;
};

void vibe_use() {
    Buffer a(64);
    Buffer b = a; // shallow copy
} // 🔴 double-free when a and b destruct
```

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

## Real-World CVEs / References

| CVE | Notes |
|-----|--------|
| [CVE-2021-3156](https://nvd.nist.gov/vuln/detail/CVE-2021-3156) | sudo heap-based buffer overflow (Baron Samedit) — illustrates critical impact of heap corruption classes adjacent to free-list abuse |
| [CVE-2015-0235](https://nvd.nist.gov/vuln/detail/CVE-2015-0235) | GHOST — glibc heap/buffer issues in name resolution path; ecosystem-wide native code risk |
| [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) | Heartbleed — memory disclosure from native TLS stack; underscores why heap hygiene and bounds matter in C libraries |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free |
| [CWE-416](https://cwe.mitre.org/data/definitions/416.html) | Use After Free (often co-located bugs) |
| [OWASP Code Review — Memory](https://owasp.org/www-project-code-review-guide/) | Review patterns for alloc/free |

Many product CVEs are filed as “heap corruption” or “use-after-free” where double-free is the root trigger; always map allocator reports carefully.

---

## Vibe-Coding Red Flags

| AI pattern | Issue |
|------------|--------|
| `free(p); free(p);` “just to be sure” | Textbook double-free |
| `destroy(x); free(x);` | Destroy already freed the object |
| Shallow copy constructors with owned pointers | Double-delete on destruct |
| `shared_ptr` + manual `delete get()` | Breaks ownership |
| Cleanup in `catch` and again after `try` | Duplicate free on exception path |
| “Fixed leak” by adding `free` without removing other free | Leak → double-free swing |
| Returning pointer that callee and caller both free | Ownership confusion |
| No ASan in the same PR that touches alloc/free | Blind refactor |

**Review mantra:** *Every `malloc`/`new` has exactly one owning free/delete path — name that owner in the PR description.*

---

*KB level: L1 languages/c-cpp · CWE-415 · Pair with: use-after-free.md, buffer-overflow.md, memory-safety.md*
