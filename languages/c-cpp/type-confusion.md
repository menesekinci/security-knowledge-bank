# Type Confusion (C/C++)

> **Severity:** Critical
> **CWE:** CWE-843 (Access of Resource Using Incompatible Type)
> **AI Generation Risk:** Medium–High — unsafe casts to "fix compile errors"

---

## Vulnerability Explanation

Type confusion occurs when a program interprets memory as a type different from what it actually contains. This breaks the type system's invariants, allowing an attacker to read or write memory outside the expected object layout. The result is typically heap corruption, out-of-bounds access, or logic bypass — often leading to full remote code execution (RCE).

Common scenarios include:

- **Polymorphic downcasts:** Casting a `Base*` to `Derived*` without verifying the runtime type, especially when the object's actual type is unknown or corrupted.
- **Union misuse:** Reading a union member that differs from the last-written member, violating strict aliasing.
- **`void*` APIs:** Storing typed pointers in `void*` containers and casting them back to the wrong type (common in callback registries, event systems, and IPC dispatch).
- **JIT engine errors:** In browser JavaScript engines (V8, SpiderMonkey), incorrect JIT optimization can confuse object types, enabling memory corruption.
- **Message parsing:** Parsing binary protocols where the type tag is attacker-controlled but not validated before casting.
- **Variant/any misuse:** Using `std::any` or `boost::any` casts without proper type checks.

In browser engines, type confusion is particularly dangerous because a single crafted HTML page can trigger the bug, escape the renderer sandbox, and give the attacker arbitrary code execution in the browser process.

---

## How AI / Vibe Coding Generates This

```cpp
Base *b = factory();
auto *d = static_cast<Derived*>(b); // AI assumes type without check
d->special();
```

Or C:

```c
void *p = read_msg();
struct Admin *a = p; // no tag check
```

AI models frequently generate these patterns because they mimic "just make it compile" fixes seen in forums. A common chain is:

1. AI writes generic factory code returning `Base*`
2. Developer needs to access a derived-specific method
3. AI suggests `static_cast` as the "simplest fix"
4. No runtime type verification is added

---

## Vulnerable Code Example

```cpp
// Type confusion via untrusted message dispatch
struct Message { int type; char data[64]; };
struct LoginMsg  { char user[32]; char pass[32]; };
struct AdminMsg  { char command[64]; };

void dispatch(Message *m) {
    if (m->type == 1) {
        auto *login = static_cast<LoginMsg*>(static_cast<void*>(m));
        process_login(login);
    } else if (m->type == 2) {
        auto *admin = static_cast<AdminMsg*>(static_cast<void*>(m));
        execute(admin->command); // Attacker sets type=2 with LoginMsg payload
    }
    // No default/else — corrupted type field or type=3 passes silently
}
```

**Windows kernel-mode example:**

```c
// KMDF driver vulnerable to type confusion
NTSTATUS DispatchIoControl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf = stack->Parameters.DeviceIoControl.Type3InputBuffer; // void*
    
    // No type discrimination — casts based on IoControlCode only
    struct RequestA *reqA = (struct RequestA*)buf;
    struct RequestB *reqB = (struct RequestB*)buf; // same buffer, different layout
}
```

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

## Prevention Checklist

- [ ] No `reinterpret_cast` without threat review
- [ ] Tagged messages + length checks before dispatch
- [ ] Fuzzing with ASan/UBSan is mandatory for parsers
- [ ] Avoid polymorphic downcasts without `dynamic_cast` or `typeid` checks
- [ ] Default/else case in all type switches — reject unknown tags
- [ ] Prefer `std::variant` over manual type tagging
- [ ] Validate buffer sizes before casting — type confusion + buffer overflow = RCE
- [ ] In kernel code, validate all `IOCTL` parameters before interpreting type
- [ ] Use `-Wstrict-aliasing` and enable it as error
- [ ] JIT engine code: never trust object maps or inline caches from untrusted input

---

## Real-World CVEs / References

| CVE | Vulnerability | Impact | Ref |
|-----|--------------|--------|-----|
| CVE-2021-30517 | Type confusion in V8 < 90.0.4430.212 | RCE via crafted HTML page (CVSS 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-30517), [Chrome Release](https://chromereleases.googleblog.com/2021/05/stable-channel-update-for-desktop.html) |
| CVE-2021-30551 | Type confusion in V8 < 91.0.4472.101 | Exploited in the wild as 0-day; RCE via heap corruption (CVSS 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-30551), [Project Zero RCA](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-30551.html) |
| CVE-2023-5217 | Heap buffer overflow in libvpx vp8 encoding (type confusion chain) | Exploited in the wild; RCE (CVSS 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-5217), [Wiz Analysis](https://www.wiz.io/blog/cve-2023-4863-and-cve-2023-5217-exploited-in-the-wild) |
| CVE-2018-1038 | Windows kernel type confusion (Win7 SP1) | Elevation of privilege — logical type confusion in kernel object handling | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-1038), [XPN Exploit Blog](https://blog.xpnsec.com/total-meltdown-cve-2018-1038/) |
| CVE-2024-3159 | Out-of-bounds memory access in V8 < 123.0.6312.105 | Arbitrary read/write via crafted HTML — type confusion leading to OOB | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-3159) |
| [CWE-843](https://cwe.mitre.org/data/definitions/843.html) | Access of Resource Using Incompatible Type ('Type Confusion') | Category reference | |

Browser engine type confusion CVEs are routine — track [Chrome releases](https://chromereleases.googleblog.com/) and [V8 vulnerability database](https://v8.dev/docs/vulnerability-fixes).

---

## Vibe-Coding Red Flags

- `static_cast<Derived*>(basePtr)` to "silence the compiler" without checking the real type
- `void*` soup in new C++ code — storing typed objects in untyped containers
- IPC structs without version/tag fields or magic numbers
- `reinterpret_cast` used to "treat bytes as a different struct"
- Raw union access where the discriminator is attacker-controllable
- Missing `default` case in switch dispatch — unhandled types pass through silently
- `memcpy` between unrelated struct types (type punning)
- AI-generated code that casts a buffer pointer to `struct foo*` without checking the buffer is large enough
- No `else` after `if (type == X)` — code that silently skips type validation
