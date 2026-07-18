---
source: "languages/c-cpp/insecure-random.md"
title: "Insecure Randomness (C/C++)"
heading: "intro"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 1/8
---

# Insecure Randomness (C/C++)

> **Severity:** High
> **CWE:** CWE-330 (Use of Insufficiently Random Values), CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator)
> **AI Generation Risk:** Very High — AI defaults to `rand()` / `srand(time(NULL))`

---