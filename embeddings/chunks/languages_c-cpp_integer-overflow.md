---
source: "languages/c-cpp/integer-overflow.md"
title: "🟠 Integer Overflow"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, code, critical, example, language-vuln, secure, types, what]
---

# 🟠 Integer Overflow

## What Is It?

When an integer variable exceeds the maximum value it can hold, **overflow**
occurs and the value wraps to the smallest value (or 0). In C/C++, signed integer overflow
is **Undefined Behavior (UB)** — meaning the compiler makes no guarantees about what happens.

## Why Is It Common in Vibe Coding?

AI generally:
1. Uses `int` but doesn't check the value range
2. Casts `size_t`-returning functions to `int`
3. Does NOT perform overflow checks on addition/multiplication

## Example

```c
// 💀 AI's "memory allocation":
int calculate_size(int count, int item_size) {
    return count * item_size;  // 💀 Overflow!
    // count=65536, item_size=65536 → returns 0!
    // Then malloc(0) → small buffer → buffer overflow!
}

void* allocate_items(int count, int item_size) {
    int total = calculate_size(count, item_size);
    return malloc(total);  // if total=0, a very small memory
}
```

## Secure Code

```c
// ✅ Safe alternative:
#include <stdckdint.h>  // C23+

bool calculate_size(size_t count, size_t item_size, size_t* result) {
    // C23's built-in overflow check:
    if (ckd_mul(result, count, item_size)) {
        return false;  // overflow occurred
    }
    return true;
}

// For C11/C17:
#include <limits.h>
bool safe_multiply(size_t a, size_t b, size_t* result) {
    if (a > 0 && b > SIZE_MAX / a) {
        return false;  // overflow!
    }
    *result = a * b;
    return true;
}
```

```cpp
// C++20 with constexpr:
#include <cstdint>
constexpr bool safe_add(int32_t a, int32_t b, int32_t& result) {
    return !__builtin_add_overflow(a, b, &result);
}

// Or modern C++ library — Microsoft SafeInt (header "SafeInt.hpp"):
#include "SafeInt.hpp"
// SafeInt performs the MULTIPLY itself and throws on arithmetic overflow:
SafeInt<size_t> total = SafeInt<size_t>(count) * item_size;  // throws SafeIntException

// NOTE: gsl::narrow<int>(count * item_size) would NOT catch this — the
// multiply `count * item_size` overflows FIRST; gsl::narrow only throws
// (gsl::narrowing_error) if the *already-computed* value doesn't fit the
// target type. Check the arithmetic itself, not just the narrowing cast.
```

## Critical Types in C/C++

| Type | Min | Max | Overflow? |
|------|-----|-----|-----------|
| `int32_t` / `int` | -2³¹ | 2³¹-1 | Signed → UB |
| `uint32_t` | 0 | 2³²-1 | Wrap around (defined) |
| `size_t` | 0 | 2⁶⁴-1 (64-bit) | Wrap around |
| `int64_t` | -2⁶³ | 2⁶³-1 | Signed → UB |

## Prevention Methods

| Rule | Description |
|------|-------------|
| Use `__builtin_add_overflow` | GCC/Clang built-in, detects overflow |
| Use `stdckdint.h` (C23) | Standard overflow detection |
| SafeInt library (C++) | Microsoft's safe integer wrapper (header `SafeInt.hpp`), separate from GSL |
| `-ftrapv` flag | Crash on overflow (makes it unexploitable) |
| `-fsanitize=undefined` | Catch UB at runtime |

## Critical Rule for Vibe Coding
```
Always check for overflow in all arithmetic operations.
Don't use count * size without overflow checking.
Remember that implicit casts (size_t → int) cause narrowing.
```

---

**Severity: 🟠 High** — Overflow → heap overflow → RCE.
**CWE: CWE-190 (Integer Overflow)**
