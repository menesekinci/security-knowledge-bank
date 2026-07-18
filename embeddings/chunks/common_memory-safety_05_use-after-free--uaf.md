---
source: "common/memory-safety.md"
title: "Memory Safety — Buffer Overflow, Use-After-Free"
heading: "Use-After-Free (UAF)"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [buffer, common-vuln, out-of-bounds, overflow, read, use-after-free, vibe, what]
chunk: 5/10
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