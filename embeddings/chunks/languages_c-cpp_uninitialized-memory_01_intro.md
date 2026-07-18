---
source: "languages/c-cpp/uninitialized-memory.md"
title: "Uninitialized Memory Use (C/C++)"
heading: "intro"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 1/8
---

# Uninitialized Memory Use (C/C++)

> **Severity:** High to Critical (info leak → key recovery; sometimes control-flow hijack)  
> **CWE:** CWE-457 (Use of Uninitialized Variable), CWE-908 (Use of Uninitialized Resource), CWE-1188 (Insecure Default Initialization of Resource)  
> **AI Generation Risk:** High — models omit initialization for “performance,” partially fill structs, and confuse `malloc` with zeroed allocators

---