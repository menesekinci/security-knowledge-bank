---
source: "languages/c-cpp/type-confusion.md"
title: "Type Confusion (C/C++)"
heading: "Secure Code Fix"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 5/8
---

## Secure Code Fix

### Discriminated variants (C++17 `std::variant`)

```cpp
#include <variant>
#include <iostream>

struct LoginMsg  { std::string user; std::string pass; };
struct AdminMsg  { std::string command; };
struct ShutdownMsg { int reason; };

using Message = std::variant<LoginMsg, AdminMsg, ShutdownMsg>;

void handle(const Message& msg) {
    std::visit([](const auto& m) {
        using T = std::decay_t<decltype(m)>;
        if constexpr (std::is_same_v<T, LoginMsg>) {
            authenticate(m.user, m.pass);
        } else if constexpr (std::is_same_v<T, AdminMsg>) {
            if (!is_admin_session()) throw std::runtime_error("unauthorized");
            execute(m.command);
        } else if constexpr (std::is_same_v<T, ShutdownMsg>) {
            graceful_shutdown(m.reason);
        }
    }, msg);
}
```

### Tagged union with exhaustive switch (C)

```c
typedef enum { MSG_LOGIN, MSG_ADMIN, MSG_SHUTDOWN, MSG_COUNT } MsgType;
typedef struct { MsgType tag; union { LoginMsg login; AdminMsg admin; }; } SafeMsg;

int handle(SafeMsg *m) {
    switch (m->tag) {
        case MSG_LOGIN:  return process_login(&m->login);
        case MSG_ADMIN:  if (!is_admin()) return -1; return process_admin(&m->admin);
        case MSG_SHUTDOWN: return do_shutdown();
        default: return -1; // exhaustive — unknown tag rejected
    }
}
```

### For C++ objects: `dynamic_cast` with RTTI

```cpp
void handle(Base *b) {
    if (auto *d = dynamic_cast<Derived*>(b)) {
        d->special();
    } else {
        // type mismatch — handle error
    }
}
```

### For JIT/renderer-level: strictly typed internal representations

- Use `reinterpret_cast` only in known-safe thin layers (serialization, binary protocols)
- Never cast between unrelated class hierarchies
- Fuzz all parsing paths with ASan/UBSan enabled
- Validate type tags against an allowlist before dispatching

### Windows-specific mitigations

- Use `std::variant` instead of `void*` dispatch tables
- Windows kernel developers: use `IoGetCurrentIrpStackLocation` safely — validate `IoControlCode` range and buffer sizes before casts
- Enable Control Flow Guard (CFG) and Address Sanitizer for kernel code
- Validate `TYPE3INPUT`s against expected structure sizes

---