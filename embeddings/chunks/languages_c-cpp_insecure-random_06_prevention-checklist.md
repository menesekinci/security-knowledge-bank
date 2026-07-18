---
source: "languages/c-cpp/insecure-random.md"
title: "Insecure Randomness (C/C++)"
heading: "Prevention Checklist"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] Never `rand()` / `srand()` for security
- [ ] Use OS CSPRNG: `/dev/urandom`, `getrandom()`, `BCryptGenRandom`, `SecRandomCopyBytes`
- [ ] Session IDs / tokens must have ≥ 128 bits of entropy
- [ ] Code review ban-list: `srand`, `rand`, `mt19937` for security, `std::default_random_engine`
- [ ] Verify `std::random_device::entropy()` on every platform you target
- [ ] Never use `time()` as seed for security PRNG — attacker can narrow to ±1 second
- [ ] Avoid sleep-based "randomization" — `srand(time(NULL) + usleep(rand()%1000))` is still predictable
- [ ] Test with `ent` or Dieharder on your RNG output before relying on it for crypto
- [ ] Use `secrets`-style API where available (Python `secrets`, C++ wrapper over OS CSPRNG)
- [ ] Guard against fd exhaustion: always check `/dev/urandom` open/read return values

---