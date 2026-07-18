---
source: "languages/c-cpp/race-conditions.md"
title: "🟠 C/C++ Race Conditions (TOCTOU)"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, example, language-vuln, prevention, what]
---

# 🟠 C/C++ Race Conditions (TOCTOU)

## What Is It?
Time-of-Check to Time-of-Use — the resource changes between checking it and using it. Classic example: file checks.

## Example
```c
// 💀 VULNERABLE:
if (access("config.json", R_OK) != 0) {  // CHECK
    // At this moment, the attacker can replace config.json with a symlink!
    return -1;
}
FILE* f = fopen("config.json", "r");  // USE → which is actually /etc/passwd! 💀

// ✅ SECURE:
FILE* f = fopen("config.json", "r");  // Open in one operation
if (f == NULL) {
    return -1;
}
// Check after opening the file
```

## Prevention
- Make CHECK and USE atomic
- Use `fopen()` directly, don't check with `access()` first
- Modern C++: open the file with fstream, handle exceptions

---

**Severity: 🟠 High** — Privilege escalation.
**CWE: CWE-367**
