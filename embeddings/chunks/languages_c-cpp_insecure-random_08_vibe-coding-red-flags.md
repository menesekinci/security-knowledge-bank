---
source: "languages/c-cpp/insecure-random.md"
title: "Insecure Randomness (C/C++)"
heading: "Vibe-Coding Red Flags"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe-Coding Red Flags

- `srand(time(NULL))` anywhere near authentication, tokens, or keys
- Token generation with `% 1000000` or `% 99999` — tiny output space
- "Random" UUID v1 used as a secret — v1 is timestamp-based and fully predictable
- `rand()` casting to `char` for password generation — trivial to brute-force
- `std::mt19937` seeded with `std::random_device{}()` used for "encryption" or "token generation"
- Self-rolled PRNGs (XOR-shift, LCG hand-tuned) in security contexts
- `std::random_device {}()` used without checking `entropy()`
- Hardcoded or file-loaded seeds for "deterministic testing" deployed to production
- Using `std::shuffle` for "random" selection from a deck of cards or lottery numbers
- Sleeping between `srand` calls to "add randomness" — this only changes the seed by < 10 values