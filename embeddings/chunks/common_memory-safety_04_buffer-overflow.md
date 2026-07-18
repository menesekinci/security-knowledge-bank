---
source: "common/memory-safety.md"
title: "Memory Safety — Buffer Overflow, Use-After-Free"
heading: "Buffer Overflow"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [buffer, common-vuln, out-of-bounds, overflow, read, use-after-free, vibe, what]
chunk: 4/10
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