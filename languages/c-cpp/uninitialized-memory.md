# Uninitialized Memory Use (C/C++)

> **Severity:** High to Critical (info leak → key recovery; sometimes control-flow hijack)  
> **CWE:** CWE-457 (Use of Uninitialized Variable), CWE-908 (Use of Uninitialized Resource), CWE-1188 (Insecure Default Initialization of Resource)  
> **AI Generation Risk:** High — models omit initialization for “performance,” partially fill structs, and confuse `malloc` with zeroed allocators

---

## Vulnerability Explanation

**Uninitialized memory** means reading storage whose value is not a determinate result of the abstract machine — stack slots, heap from `malloc`/`operator new` without initialization, or padding holes in structs. In practice:

1. **Information disclosure** — residual data from prior stack frames or heap chunks may contain passwords, keys, pointers ASLR slides, or other tenants’ data in clever heap scenarios.
2. **Non-deterministic control flow** — branches on uninitialized flags; security checks that “usually work” in debug (zeroed stacks) and fail open/closed randomly in production.
3. **Undefined behavior (UB)** in C/C++ — compilers may assume uninitialized reads never happen and optimize aggressively (deleting “dead” checks, miscompiling).
4. **Kernel / cross-process leaks** — classic class of bugs when kernels copy uninitialized struct padding to userspace.

Sources of uninitialized storage:

| Allocator / storage | Zeroed? |
|---------------------|---------|
| Stack locals | No (unless compiler/debug pattern) |
| `malloc` / `realloc` new region | No |
| `calloc` / `zalloc` | Yes |
| `new T` for trivial types | No |
| `new T{}` / value init | Yes (for appropriate types) |
| `std::vector<T>(n)` | Default-inserts (zeros for POD in practice via value init rules — know your type) |
| mmap without MAP_ANONYMOUS zero guarantees carefully | OS-dependent; anonymous is zero-filled on demand on major OSes |

Padding bytes in structs are a frequent leak channel even when every named field was set.

---

## How AI / Vibe Coding Generates This

- Uses `malloc(sizeof(T))` then sets only some fields; remaining fields/padding leak via `write`/`send`/`memcpy` of whole struct.
- Declares `int auth;` and only sets it on success path; failure path reads it.
- Ports Java/Go mental model (“fields default to zero”) into C.
- “Optimized” crypto examples that skip wiping or skip initializing IV/nonce buffers (sometimes also confuses uninit with lack of random — see insecure-random.md).
- Partial `memcpy` into buffers then treats full buffer as defined.
- C++: default constructors that leave members uninitialized; AI-generated structs without constructors.
- Kernel-style `copy_to_user` of stack structs without `memset` first — AI copies driver snippets incorrectly.
- Mixing `operator new` with C APIs that expect zeroed memory.

---

## Vulnerable Code Example (realistic)

### C — stack + heap info leak

```c
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct UserResponse {
    int uid;
    int role;
    char name[32];
    /* padding may exist */
    char token[32];
};

/* 🔴 Sends entire struct including uninitialized token/padding */
void handle_login(int client_fd, int uid, const char *name) {
    struct UserResponse resp;  /* uninitialized */
    resp.uid = uid;
    resp.role = 1;
    strncpy(resp.name, name, sizeof(resp.name) - 1);
    resp.name[sizeof(resp.name) - 1] = '\0';
    /* forgot token and padding */

    write(client_fd, &resp, sizeof(resp));  /* 🔴 leak */
}

char *build_packet(size_t n) {
    char *buf = malloc(n);     /* 🔴 uninitialized heap */
    if (!buf) return NULL;
    /* only fill first 4 bytes */
    buf[0] = 'O'; buf[1] = 'K'; buf[2] = '\n'; buf[3] = '\0';
    return buf; /* caller may send all n bytes */
}

int check_access(void) {
    int allowed;               /* 🔴 uninitialized */
    if (getuid() == 0) {
        allowed = 1;
    }
    /* non-root: allowed never set */
    return allowed;            /* UB / random allow */
}
```

### C++ — trivial member left cold

```cpp
struct Config {
    bool enforce_tls;
    int max_conn;
    // AI forgot constructors
};

bool start_server(Config c) {
    if (c.enforce_tls) { /* 🔴 indeterminate if default-constructed poorly */
        /* ... */
    }
    return true;
}

void vibe() {
    Config c; // members uninitialized for this trivial layout
    start_server(c);
}
```

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

## Prevention Checklist

- [ ] Initialize all locals at declaration when practical (`int x = 0;`)
- [ ] `memset`/`= {}` structs before partial fills if binary-copied
- [ ] Prefer `calloc` when zero-fill is required; document when `malloc` is intentional
- [ ] Default-deny security flags (uninit must not mean “allow”)
- [ ] Never `write`/`send` raw structs across trust boundaries; use defined encoding
- [ ] Enable MSan/Valgrind in CI for native components
- [ ] C++: in-class member initializers; `= default` constructors that init all fields
- [ ] Kernel/driver code: zero before `copy_to_user`
- [ ] Review AI patches that remove “redundant” `memset` for “performance”
- [ ] Static analysis + treat warnings as errors in security-sensitive modules

---

## Real-World CVEs / References

| CVE / ref | Relevance |
|-----------|-----------|
| [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) | Heartbleed — out-of-bounds read of OpenSSL heap; iconic **memory content disclosure** class (bounds, not classic uninit, but same impact taxonomy: secret material leaves process) |
| [CVE-2015-0235](https://nvd.nist.gov/vuln/detail/CVE-2015-0235) | GHOST — glibc; native library memory safety impact |
| [CVE-2015-7547](https://nvd.nist.gov/vuln/detail/CVE-2015-7547) | glibc `getaddrinfo` — stack buffer issues in widely deployed C code |
| [CWE-457](https://cwe.mitre.org/data/definitions/457.html) | Use of Uninitialized Variable |
| [CWE-908](https://cwe.mitre.org/data/definitions/908.html) | Use of Uninitialized Resource |
| Numerous kernel CVEs | Uninitialized struct padding leaked to userspace (search NVD for “uninitialized” + Linux kernel) |

Heartbleed is included as the industry reference for **catastrophic secret leakage from native memory mishandling**; pair with pure CWE-457 cases in your own code reviews.

---

## Vibe-Coding Red Flags

| Pattern | Risk |
|---------|------|
| `malloc` + partial field init + `sizeof` send | Padding/field leak |
| `int flag;` without `= 0` on deny path | Auth bypass lottery |
| AI removes `memset` as “unnecessary” | Reintroduces leaks |
| Java-style assumption that fields are zero | Wrong for C stack |
| Logging “debug dumps” of raw structs | Operational secret leak |
| `new Foo` without `{}` or member init | Indeterminate members |
| No MSan in CI for crypto/auth code | Silent UB |
| Using uninitialized buffer as RNG entropy | Catastrophic crypto fail |

**Rule:** *If memory leaves the process (wire, disk, syscall), every byte must be intentionally defined.*

---

*KB level: L1 languages/c-cpp · CWE-457 · Pair with: buffer-overflow.md, insecure-random.md, memory-safety.md*
