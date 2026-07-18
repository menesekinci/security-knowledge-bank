---
source: "languages/c-cpp/unsafe-functions.md"
title: "🔴 C/C++ Unsafe Functions"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, example, functions, gets, language-vuln, rule, that]
---

# 🔴 C/C++ Unsafe Functions

## Functions That Should Never Be Used

| Function | Risk | Use Instead |
|-----------|------|-------------------|
| `gets()` | Buffer overflow (no bounds) | `fgets()` |
| `strcpy()` | Overflow | `strlcpy()` (`strncpy` does *not* NUL-terminate on truncation) |
| `strcat()` | Overflow | `strncat()`, `strlcat()` |
| `sprintf()` | Overflow | `snprintf()` |
| `scanf("%s")` | Overflow | `fgets()`, bounded `scanf()` |
| `system()` | Command injection | `execve()` |
| `mktemp()` | Race condition | `mkstemp()` |
| `itoa()` | Non-standard | `snprintf()` |

## Example: gets() → How Is It Still Being Used?
```c
// 💀 What the AI wrote (may have seen it in training data):
char buf[64];
gets(buf);  // gets() was REMOVED in C11 (deprecated in C99). Legacy/pre-C11
            // code and training data still contain it — open to overflow.
```

## Rule for Vibe Coding
```
When writing C code, DO NOT USE the following:
gets, strcpy, strcat, sprintf, scanf(%s), system
Always use their safe alternatives.
```

---

**Severity: 🔴 Critical**
