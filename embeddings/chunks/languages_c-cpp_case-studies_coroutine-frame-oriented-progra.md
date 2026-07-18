---
source: "languages/c-cpp/case-studies/coroutine-frame-oriented-programming-cfop.md"
title: "Coroutine Frame-Oriented Programming (CFOP): Breaking C++ CFI via Coroutines"
category: "case-study"
language: "c-cpp"
severity: "high"
tags: [attack, c-cpp, case-study, cfop, chain, discovery, impact, overview]
---

# Coroutine Frame-Oriented Programming (CFOP): Breaking C++ CFI via Coroutines

**Language:** C++20 (Coroutines)
**Vulnerability Type:** Code-Reuse Attack (CFI Bypass)
**CVE:** N/A (Design-Level Vulnerability)
**Date:** USENIX Security 2025 / Black Hat USA 2025
**Researchers:** CISPA Helmholtz Center (M. Bajo et al.)

## Overview

**Coroutine Frame-Oriented Programming (CFOP)** is a novel code-reuse attack that exploits the insecure implementation of C++20 coroutines to bypass state-of-the-art Control Flow Integrity (CFI) protections on **both Linux and Windows**.

## The Discovery

CISPA researchers found that **all existing implementations** of C++ coroutines across GCC, Clang, and MSVC are vulnerable. The paper was presented at **USENIX Security 2025** and demonstrated at **Black Hat USA 2025**.

**Paper:** https://www.usenix.org/conference/usenixsecurity25/presentation/bajo
**Research Page:** https://syssec.cispa.io/coroutine-cfop/

## How CFOP Works

```
Traditional Exploit:          CFOP Exploit:
┌─────────────────┐          ┌──────────────────────┐
│ Overwrite return │          │ Allocate coroutine   │
│ address on stack │          │ frame on heap        │
├─────────────────┤          ├──────────────────────┤
│ CFI detects it  │          │ CFI MISSES it!       │
└─────────────────┘          │ Coroutine frames are │
                              │ NOT protected by CFI │
                              └──────────────────────┘
```

C++ coroutine frames are heap-allocated and contain:
- Suspended local variables
- **Function pointers** (not protected by CFI!)
- Return addresses
- Promise type information

## Attack Chain

1. **Trigger coroutine suspension** — Allocate coroutine frame on heap
2. **Corrupt coroutine frame** — Via use-after-free, heap overflow, etc.
3. **Modify function pointers** — Inside the frame (CFI-unprotected)
4. **Resume coroutine** — Execution hijacked via corrupted frame
5. **Achieve RCE** — Chain with other primitives

## Impact

| Platform | CFI Scheme | Bypassed? |
|----------|-----------|-----------|
| Windows | Control Flow Guard (CFG) | ✅ Yes |
| Linux | LLVM CFI | ✅ Yes |
| Linux | Intel CET | ✅ Yes |
| Linux | Shadow Stacks | ✅ Yes |

## Affected Compilers

| Compiler | Status |
|----------|--------|
| **GCC** (all versions) | Vulnerable |
| **Clang/LLVM** (all versions) | Vulnerable |
| **MSVC** (all versions) | Vulnerable |

## Mitigation

Currently no complete mitigation exists because:
1. Coroutine frames are intentionally heap-allocated (language requirement)
2. CFI schemes don't protect heap-allocated function pointers
3. Fix requires changes to the C++ standard or ABI

## Source URLs

- https://cispa.de/en/cfop
- https://www.usenix.org/conference/usenixsecurity25/presentation/bajo
- https://syssec.cispa.io/coroutine-cfop/
- https://github.com/coroutine-cfop/cfop
- https://i.blackhat.com/BH-USA-25/Presentations/USA-25-Bajo-Coroutine-Frame-Oriented-Programming-Breaking.pdf
- https://dl.acm.org/doi/10.5555/3766078.3766458
