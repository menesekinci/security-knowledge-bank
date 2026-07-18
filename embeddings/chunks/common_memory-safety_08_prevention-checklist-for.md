---
source: "common/memory-safety.md"
title: "Memory Safety — Buffer Overflow, Use-After-Free"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [buffer, common-vuln, out-of-bounds, overflow, read, use-after-free, vibe, what]
chunk: 8/10
---

## Prevention Checklist for AI Prompts

```
✅ MEMORY SAFETY REQUIREMENTS:
- For new projects, prefer memory-safe languages (Rust, Go, Java, Python)
- If using C/C++: enable ALL compiler warnings (-Wall -Wextra -Werror)
- Use static analysis tools (Coverity, Clang Static Analyzer, Cppcheck)
- Replace unsafe functions: strcpy→strlcpy/strncpy, sprintf→snprintf, gets→fgets
- Use std::string and std::vector instead of raw C arrays
- Use smart pointers (unique_ptr, shared_ptr) instead of raw pointers
- Sanitize builds: AddressSanitizer (-fsanitize=address), UndefinedBehaviorSanitizer
- Always validate array indices and buffer sizes
- Use bounds-checked containers (std::array, std::span)
- Never use memset/memcpy on C++ objects
```

### Compiler & Tool Flags for Safety

```bash
# GCC/Clang — enable all safety features
gcc -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -O2 -fsanitize=address,undefined

# Clang static analyzer
scan-build gcc -c myfile.c

# Valgrind (runtime)
valgrind --leak-check=full ./myprogram
```

---