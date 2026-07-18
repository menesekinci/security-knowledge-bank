---
source: "languages/c-cpp/double-free.md"
title: "Double-Free Memory Corruption (C/C++)"
heading: "Vulnerable Code Example (realistic)"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 4/8
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