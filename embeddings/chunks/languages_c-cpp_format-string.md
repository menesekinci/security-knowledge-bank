---
source: "languages/c-cpp/format-string.md"
title: "🔴 Format String Attacks"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, code, does, example, language-vuln, methods, prevention, secure, what]
---

# 🔴 Format String Attacks

## What Is It?

Passing user input directly as a **format string** to the `printf()` family
of functions. With format specifiers like %x, %n, %s, an attacker can:
- Read data from the stack (info leak)
- Write to memory (RCE)

## How Does It Appear in Vibe Coding?

```
Prompt: "Write a C function that prints the username"
AI: 
void print_username(char* name) {
    printf(name);  // 💀 FORMAT STRING!
}
```

AI prefers writing `printf(name)` instead of `printf("%s", name)`
because it looks "short and clean".

## Example

```c
// 💀 VULNERABLE:
void log_message(char* user_input) {
    printf(user_input);  // Format string!
}

// User input: "%x %x %x %x %x %x %x %x"
// Output: Leaks hex values from the stack (ASLR bypass!)
// User input: "%s%s%s%s%s%s%s%s"
// Output: Reads strings in memory (info leak!)
// User input: "\x10\x20\x30\x40%n"
// Output: Writes to memory (RCE!)
```

## Secure Code

```c
// ✅ SAFE:
void log_message(char* user_input) {
    printf("%s", user_input);  // Format string is constant!
}
```

## Prevention Methods

| Rule | Description |
|------|-------------|
| **Never make format string variable** | Use `printf("%s", str)` instead of `printf(str)` |
| Use static analysis | gcc `-Wformat-security` flag |
| Use modern C++ | `std::cout << str;` (no format string vulnerability) |

---

**Severity: 🔴 Critical** — Information leak + RCE.
**CWE: CWE-134 (Use of Externally-Controlled Format String)**
