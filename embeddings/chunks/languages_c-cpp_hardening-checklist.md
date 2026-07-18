---
source: "languages/c-cpp/hardening-checklist.md"
title: "⚙️ C/C++ Security Hardening Checklist"
category: "checklist"
language: "c-cpp"
severity: "medium"
tags: [c-cpp, checklist, code, compiler, concurrency, flags, memory, modern, safety, security]
---

# ⚙️ C/C++ Security Hardening Checklist

> Items to check in every C/C++ project before deployment.

## ✅ Compiler Flags
- [ ] `-fstack-protector-strong` (stack canary)
- [ ] `-D_FORTIFY_SOURCE=2` (buffer overflow detection)
- [ ] `-Wformat -Wformat-security` (format string warning)
- [ ] `-fPIE -pie` (position independent executable)
- [ ] `-z noexecstack` (non-executable stack)
- [ ] `-z relro -z now` (full RELRO)
- [ ] `-fsanitize=address` (ASan) in development
- [ ] `-fsanitize=undefined` (UBSan) in development

## ✅ Code Security
- [ ] Are `gets()`, `sprintf()`, `strcpy()`, `strcat()`, `scanf(%s)` avoided?
- [ ] Are `snprintf()`, `strncpy()`, `strlcpy()`, `fgets()` used?
- [ ] Is there no `printf(user_input)` format string risk?
- [ ] Is NULL checked after `malloc`/`calloc`?
- [ ] Is the pointer set to NULL after `free()`?
- [ ] Is integer overflow checked? (safeint, __builtin_add_overflow)

## ✅ Memory Safety
- [ ] Are buffer boundaries checked on every operation?
- [ ] Is there no use-after-free risk? (are smart pointers used?)
- [ ] Has a double free check been performed?
- [ ] Is there no use of uninitialized memory?
- [ ] Are `std::unique_ptr` / `std::shared_ptr` preferred?

## ✅ Concurrency
- [ ] Is there no data race risk? (test with ThreadSanitizer)
- [ ] Is mutex locking used correctly? (lock_guard / unique_lock)
- [ ] Has deadlock risk been evaluated?

## ✅ Modern C++
- [ ] Are smart pointers used instead of raw pointers?
- [ ] Is RAII used instead of `new`/`delete`?
- [ ] Is `<random>` used instead of `rand()`?

## 🛡️ Vibe Coding Extras
- [ ] Have the C-style string operations written by the AI been checked?
- [ ] Is the AI's `printf()` format string usage safe?
- [ ] Have the pointer operations suggested by the AI been manually verified?
