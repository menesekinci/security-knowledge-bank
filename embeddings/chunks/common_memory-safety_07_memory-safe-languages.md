---
source: "common/memory-safety.md"
title: "Memory Safety — Buffer Overflow, Use-After-Free"
heading: "Memory-Safe Languages"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [buffer, common-vuln, out-of-bounds, overflow, read, use-after-free, vibe, what]
chunk: 7/10
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