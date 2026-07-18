---
source: "languages/c-cpp/buffer-overflow.md"
title: "🔴 Buffer Overflow"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, code, example, language-vuln, methods, prevention, secure, what]
---

# 🔴 Buffer Overflow

## What Is It?

It is when a program writes more data to an array (buffer) than its capacity.
This leads to **overwriting adjacent memory**. An attacker
can use this to **modify the return address** and execute their own code.

## Why Is It Common in Vibe Coding?

In C/C++, AI most often produces buffer overflows in the following patterns:

1. Uses **`gets()`** (NO bounds checking)
2. Does not use **`strncpy()`** instead of `strcpy()`
3. Does not check **array indices**
4. Takes unlimited input with **`scanf("%s")`**

## Example

```c
// 💀 AI's "simple" login:
#include <stdio.h>
#include <string.h>

int main() {
    char password[8];  // ONLY 8 bytes!
    int auth = 0;
    
    printf("Enter password: ");
    gets(password);  // 💀 NO BOUNDS! Enter 100 chars = overflow
    
    if (strcmp(password, "secret") == 0) {
        auth = 1;
    }
    
    if (auth) {
        printf("Access granted!\n");
    }
    return 0;
}
// Input: AAAAAAAAAAAAAAAAAAAA (20+ 'A')
// → password buffer overflows, overrides auth variable
// → "Access granted!" 💀
```

## Secure Code

```c
// ✅ Safe alternative:
#include <stdio.h>
#include <string.h>

#define MAX_PASSWORD 64

int main() {
    char password[MAX_PASSWORD];
    int auth = 0;
    
    printf("Enter password: ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
        return 1;
    }
    // Remove trailing newline
    password[strcspn(password, "\n")] = 0;
    
    if (strcmp(password, "secret") == 0) {
        auth = 1;
    }
    
    if (auth) {
        printf("Access granted!\n");
    }
    return 0;
}
```

## Prevention Methods

| What to Do? | Why? |
|-------------|------|
| Do NOT use `gets()` | No bounds checking, an attacker's dream |
| Use `strncpy()` or `strlcpy()` instead of `strcpy()` | Specify the destination buffer size |
| Don't use `sprintf()`, use `snprintf()` | Prevents buffer overflow in formatted output |
| Don't use `scanf("%s")`, use `fgets()` | Limit input size |
| Use stack canaries | Compiler protection (`-fstack-protector`) |
| Enable ASLR/DEP/NX | OS-level protection |

## Critical Rule for Vibe Coding
```
When writing C code:
- NEVER use gets()
- Always bounds-check every array operation
- Use strncpy, snprintf, fgets
- Enable compiler protections: -fstack-protector -D_FORTIFY_SOURCE=2
- If you can use modern C++, use std::string, std::vector, std::array
```

## Real World Examples
- **Morris Worm (1988)**: `gets()` buffer overflow compromised 6000+ UNIX machines
- **Heartbleed (CVE-2014-0160)**: OpenSSL buffer over-read — millions of servers
- **BlueKeep (CVE-2019-0708)**: RDP buffer overflow — wormable
- **CVE-2024-21887**: Ivanti VPN buffer overflow — RCE

---

**Severity: 🔴 Critical** — The most classic vulnerability leading directly to RCE.
**CWE: CWE-119 (Buffer Overflow)**
**OWASP: A06:2021 (Vulnerable and Outdated Components)**
