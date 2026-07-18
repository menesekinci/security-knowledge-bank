---
source: "languages/c-cpp/double-free.md"
title: "Double-Free Memory Corruption (C/C++)"
heading: "intro"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 1/8
---

# Double-Free Memory Corruption (C/C++)

> **Severity:** Critical (often leads to RCE or privilege escalation via heap corruption)  
> **CWE:** CWE-415 (Double Free), related CWE-416 (Use After Free), CWE-825 (Expired Pointer Dereference)  
> **AI Generation Risk:** High — AI frequently inserts redundant `free`/`delete` in error paths, cleanup helpers, and “defensive” duplicate teardown without ownership discipline

---