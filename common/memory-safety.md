# Memory Safety — Buffer Overflow, Use-After-Free

**CWE:** CWE-787 (Out-of-bounds Write), CWE-125 (Out-of-bounds Read), CWE-416 (Use After Free), CWE-119 (Memory Buffer Errors)
**CWE Top 25 2024:** #2 (Out-of-bounds Write), #6 (Out-of-bounds Read), #8 (Use After Free)

---

## What Are Memory Safety Vulnerabilities?

Memory safety vulnerabilities occur when code **accesses memory outside allocated bounds** or **uses memory after it has been freed**. These are the most dangerous class of vulnerability in systems programming — they can lead to:

- **Remote Code Execution (RCE):** Overwriting function pointers or return addresses
- **Information Disclosure:** Reading memory that contains other users' data or secrets
- **Denial of Service:** Causing segmentation faults
- **Privilege Escalation:** Corrupting kernel memory

**The root cause:** Languages like C and C++ don't enforce memory safety at compile time. The programmer is responsible for ensuring every pointer dereference, array access, and allocation is valid.

## Why Vibe Coding Makes This Worse

- **AI generates C/C++ without safety checks:** AI omits bounds checking, size validation, and null pointer checks
- **AI uses unsafe functions:** `strcpy()`, `sprintf()`, `gets()`, `scanf()` — all buffer overflow risks
- **AI doesn't understand manual memory management:** Generated code misses `free()` calls or uses-after-free
- **AI picks C for performance:** When asked for "fast code," AI defaults to C/C++ without memory safety training
- **AI-generated FFI/bindings:** Calling C from Python/JS creates memory safety risks at the boundary

---

## Buffer Overflow

Writing more data into a buffer than it was allocated to hold.

### Vulnerable Code (C)

```c
#include <string.h>
#include <stdio.h>

void process_input(char *user_input) {
    char buffer[64];  // Stack buffer, 64 bytes

    // 🔴 VULNERABLE: no bounds check
    strcpy(buffer, user_input);
    // If user_input > 64 bytes, buffer overflows onto stack
    // Attacker can overwrite the return address → RCE
}

int main(int argc, char **argv) {
    process_input(argv[1]);  // Try with 100 'A's → crash
    return 0;
}
```

### Vulnerable Code (C++)

```cpp
#include <iostream>

void process_name(const std::string& name) {
    char buffer[32];
    // 🔴 VULNERABLE: sprintf doesn't check bounds
    sprintf(buffer, "Hello, %s!", name.c_str());
    // If name is 100 chars, buffer overflows
    std::cout << buffer << std::endl;
}
```

### Fixed Code (C)

```c
#include <string.h>
#include <stdio.h>

void process_input(char *user_input) {
    char buffer[64];

    // ✅ SAFE: strncpy with explicit length check
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination

    // ✅ EVEN BETTER: snprintf (modern, safe)
    // snprintf(buffer, sizeof(buffer), "%s", user_input);
}
```

### Fixed Code (C++)

```cpp
#include <iostream>
#include <string>

void process_name(const std::string& name) {
    // ✅ SAFE: use std::string — automatically handles size
    std::string greeting = "Hello, " + name + "!";
    std::cout << greeting << std::endl;

    // Or with fixed buffer:
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "Hello, %.20s!", name.c_str());
    // %.20s limits to 20 chars — never overflows
}
```

---

## Use-After-Free (UAF)

Accessing memory after it has been freed — the memory may have been reallocated for another purpose.

### Vulnerable Code

```cpp
#include <iostream>

class User {
public:
    char *name;
    User(const char *n) {
        name = new char[strlen(n) + 1];
        strcpy(name, n);
    }
    ~User() { delete[] name; }
    const char* getName() { return name; }
};

int main() {
    User *user = new User("Alice");

    // 🔴 VULNERABLE: use after free
    delete user;          // user is freed
    std::cout << user->getName() << std::endl;  // CRASH! Using freed memory

    // Attacker could allocate something else at that address
    User *attacker = new User("MALICIOUS_CODE");
    std::cout << user->getName() << std::endl;  // Prints "MALICIOUS_CODE"!
}
```

### Fixed Code

```cpp
#include <iostream>
#include <memory>  // smart pointers

class User {
public:
    std::string name;  // ✅ Use std::string — RAII manages memory
    User(const std::string& n) : name(n) {}
    const std::string& getName() { return name; }
};

int main() {
    // ✅ SAFE: use smart pointer
    auto user = std::make_unique<User>("Alice");
    std::cout << user->getName() << std::endl;
    // Automatically freed when unique_ptr goes out of scope

    // With shared ownership:
    auto shared_user = std::make_shared<User>("Bob");
    std::cout << shared_user->getName() << std::endl;
}
```

---

## Out-of-Bounds Read

Reading memory outside allocated buffer bounds — leaks sensitive data.

### Vulnerable Code

```c
int secret_key = 0xDEADBEEF;  // Sensitive data on stack

void read_array(int index) {
    int data[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    // 🔴 VULNERABLE: no bounds check
    int value = data[index];  // If index = -1 or index > 9 → reads adjacent memory
    printf("Value: %d\n", value);
    // index = -1 might read secret_key!
}

// Heartbleed bug was exactly this — reading extra bytes from a buffer
```

### Fixed Code

```c
void read_array(int index) {
    int data[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    // ✅ SAFE: bounds check
    if (index < 0 || index >= 10) {
        fprintf(stderr, "Index out of bounds\n");
        return;
    }
    int value = data[index];
    printf("Value: %d\n", value);
}
```

---

## Memory-Safe Languages

| Language | Memory Safe? | Notes |
|---|---|---|
| **Rust** | ✅ Yes | Ownership system guarantees safety at compile time |
| **Go** | ✅ Yes | Garbage collected, bounds-checked |
| **Java** | ✅ Yes | GC, bounds-checked arrays |
| **Python** | ✅ Yes | GC, no raw pointers |
| **JavaScript** | ✅ Yes | GC, bounds-checked |
| **C** | ❌ No | Full manual control, full responsibility |
| **C++** | ❌ Mostly No | RAII helps, but raw pointers still dangerous |
| **C++ with smart pointers** | 🟡 Partially | Eliminates UAF, but still has buffer overflows |

---

## Prevention Checklist for AI Prompts

```
✅ MEMORY SAFETY REQUIREMENTS:
- For new projects, prefer memory-safe languages (Rust, Go, Java, Python)
- If using C/C++: enable ALL compiler warnings (-Wall -Wextra -Werror)
- Use static analysis tools (Coverity, Clang Static Analyzer, Cppcheck)
- Replace unsafe functions: strcpy→strlcpy/strncpy, sprintf→snprintf, gets→fgets
- Use std::string and std::vector instead of raw C arrays
- Use smart pointers (unique_ptr, shared_ptr) instead of raw pointers
- Sanitize builds: AddressSanitizer (-fsanitize=address), UndefinedBehaviorSanitizer
- Always validate array indices and buffer sizes
- Use bounds-checked containers (std::array, std::span)
- Never use memset/memcpy on C++ objects
```

### Compiler & Tool Flags for Safety

```bash
# GCC/Clang — enable all safety features
gcc -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -O2 -fsanitize=address,undefined

# Clang static analyzer
scan-build gcc -c myfile.c

# Valgrind (runtime)
valgrind --leak-check=full ./myprogram
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Heartbleed (out-of-bounds read) | CVE-2014-0160 | Leaked private keys from memory |
| Shellshock (command injection in Bash) | CVE-2014-6271 | RCE via crafted environment variables (not a buffer overflow) |
| EternalBlue (buffer overflow in SMB) | CVE-2017-0144 | WannaCry ransomware worm |
| Stagefright (buffer overflow in Android) | CVE-2015-1538 | RCE via MMS on Android |
| Dirty Pipe (uninitialized `pipe_buffer.flags` in Linux) | CVE-2022-0847 | Privilege escalation via read-only page-cache overwrite (improper initialization, CWE-665 — not UAF) |
| iOS/macOS kernel race condition | CVE-2021-1782 | Privilege escalation, exploited in the wild |

---

## References

- [OWASP Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)
- [Microsoft — Security Development Lifecycle (memory safety)](https://www.microsoft.com/en-us/securityengineering/sdl)
- [Rust — Memory Safety](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)
