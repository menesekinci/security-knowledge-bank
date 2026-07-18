---
source: "languages/c-cpp/uninitialized-memory.md"
title: "Uninitialized Memory Use (C/C++)"
heading: "Secure Code Fix"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 5/8
---

## Secure Code Fix

### C — zero then set; calloc for heap

```c
void handle_login(int client_fd, int uid, const char *name) {
    struct UserResponse resp;
    memset(&resp, 0, sizeof(resp));  /* defines padding too */
    resp.uid = uid;
    resp.role = 1;
    strncpy(resp.name, name, sizeof(resp.name) - 1);
    /* token intentionally empty/zero or filled from secure RNG */
    write(client_fd, &resp, sizeof(resp));
}

char *build_packet(size_t n) {
    char *buf = calloc(1, n);  /* zero-initialized */
    if (!buf) return NULL;
    if (n >= 4) {
        memcpy(buf, "OK\n", 4);
    }
    return buf;
}

int check_access(void) {
    int allowed = 0;           /* explicit default deny */
    if (getuid() == 0) {
        allowed = 1;
    }
    return allowed;
}
```

### C++ — value initialization / member initializers

```cpp
struct Config {
    bool enforce_tls = true;
    int max_conn = 100;
};

// or
Config c{}; // value-initialize

// heap
auto* p = new Config{};           // value init
auto up = std::make_unique<Config>(); // default member initializers apply
```

### Tooling

- **MemorySanitizer** (`-fsanitize=memory`) catches uninitialized reads (Clang).
- **Valgrind** Memcheck.
- Compiler warnings: `-Wuninitialized -Wmaybe-uninitialized` (note: not complete).
- Prefer sending **explicit serializers** (field-by-field) over raw struct dumps to the network.

---