---
source: "common/memory-safety.md"
title: "Memory Safety — Buffer Overflow, Use-After-Free"
heading: "What Are Memory Safety Vulnerabilities?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [buffer, common-vuln, out-of-bounds, overflow, read, use-after-free, vibe, what]
chunk: 2/10
---

## What Are Memory Safety Vulnerabilities?

Memory safety vulnerabilities occur when code **accesses memory outside allocated bounds** or **uses memory after it has been freed**. These are the most dangerous class of vulnerability in systems programming — they can lead to:

- **Remote Code Execution (RCE):** Overwriting function pointers or return addresses
- **Information Disclosure:** Reading memory that contains other users' data or secrets
- **Denial of Service:** Causing segmentation faults
- **Privilege Escalation:** Corrupting kernel memory

**The root cause:** Languages like C and C++ don't enforce memory safety at compile time. The programmer is responsible for ensuring every pointer dereference, array access, and allocation is valid.