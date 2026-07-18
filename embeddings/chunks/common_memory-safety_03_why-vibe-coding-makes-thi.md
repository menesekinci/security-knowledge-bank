---
source: "common/memory-safety.md"
title: "Memory Safety — Buffer Overflow, Use-After-Free"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [buffer, common-vuln, out-of-bounds, overflow, read, use-after-free, vibe, what]
chunk: 3/10
---

## Why Vibe Coding Makes This Worse

- **AI generates C/C++ without safety checks:** AI omits bounds checking, size validation, and null pointer checks
- **AI uses unsafe functions:** `strcpy()`, `sprintf()`, `gets()`, `scanf()` — all buffer overflow risks
- **AI doesn't understand manual memory management:** Generated code misses `free()` calls or uses-after-free
- **AI picks C for performance:** When asked for "fast code," AI defaults to C/C++ without memory safety training
- **AI-generated FFI/bindings:** Calling C from Python/JS creates memory safety risks at the boundary

---