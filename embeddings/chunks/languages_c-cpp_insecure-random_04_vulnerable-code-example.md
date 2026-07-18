---
source: "languages/c-cpp/insecure-random.md"
title: "Insecure Randomness (C/C++)"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example

```c
// Session ID generation — 8 hex chars from rand() = 32 bits entropy
char session_id[9];
sprintf(session_id, "%08x", rand()); // Predictable within seconds
```

```cpp
// C++17 AI-generated "random password" — all predictable
#include <random>
#include <iostream>

std::string generate_password(int len) {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::mt19937 rng(std::random_device{}()); // std::random_device may be deterministic!
    std::uniform_int_distribution<> dist(0, sizeof(charset)-2);
    std::string pwd;
    for (int i = 0; i < len; i++) pwd += charset[dist(rng)];
    return pwd;
}
```

**Why this is still weak:** `std::random_device` on some platforms (MinGW, older MSVC) returns a deterministic sequence — it is not guaranteed to be a CSPRNG. The C++ standard only says it should be "non-deterministic" where possible, but does not mandate cryptographic quality.

```c
// Router WPS PIN generation — real-world (CVE-2016-10180)
srand(time(0));
unsigned int pin = rand(); // D-Link DWR-932B
```

---