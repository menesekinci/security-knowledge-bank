---
source: "languages/c-cpp/insecure-random.md"
title: "Insecure Randomness (C/C++)"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

```c
srand(time(NULL));
int token = rand();
```

Appears in countless tutorials; models reproduce it for "OTP" and "API keys".

```cpp
// AI-generated "secure token" — actually trivial to predict
#include <cstdlib>
#include <ctime>

std::string generate_token() {
    srand(static_cast<unsigned>(time(nullptr)));
    int val = rand();
    return std::to_string(val);
}
```

Models trained on StackOverflow data frequently suggest:

- `srand(time(0))` for "unique" identifiers
- `rand() % N` for "random selection" in security contexts
- `std::default_random_engine` seeded with `time(0)` in "encryption" code
- Rolling-your-own XOR-shift or LCG for "lightweight crypto"

---