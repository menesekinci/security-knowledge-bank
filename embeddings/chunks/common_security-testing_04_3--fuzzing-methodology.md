---
source: "common/security-testing.md"
title: "🔬 Security Testing Methodology"
heading: "3. Fuzzing Methodology"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, fuzzing, methodology, penetration, testing, tool, types]
chunk: 4/8
---

## 3. Fuzzing Methodology

Fuzzing finds bugs that static analysis misses — memory corruption, logic errors, edge cases.

### Language-Specific Fuzzers

| Language   | Fuzzer                              | Best For                          |
|------------|--------------------------------------|-----------------------------------|
| **C/C++**  | AFL++, libFuzzer, Honggfuzz          | Memory corruption, buffer overflow |
| **Rust**   | cargo-fuzz (libFuzzer), AFL.rs       | Unsafe code, panic safety         |
| **Go**     | go-fuzz, syzkaller                   | Protocol parsing, input handling  |
| **Python** | Atheris (libFuzzer), python-afl      | Deserialization, parsing          |
| **Java**   | Jazzer (libFuzzer), JQF              | Deserialization, expression injection |
| **Solidity**| Echidna, Foundry fuzz, Diligence Fuzzing | Smart contract invariants    |
| **JS/TS**  | Jazzer.js, fuzzilli                  | JSON parsing, crypto operations   |
| **Swift**  | libFuzzer (via Swift), SwiftFuzz     | Codable deserialization           |

### Fuzzing Workflow

```
1. IDENTIFY TARGETS
   └─ Public API endpoints, file parsers, deserialization points,
      expression evaluators, crypto routines

2. CREATE FUZZ HARNESS
   └─ Write a thin wrapper that feeds fuzzer-generated input to the target

3. CHOOSE COVERAGE GUIDANCE
   └─ Code coverage (AFL++, libFuzzer)
   └─ Sanitizer coverage (ASan, UBSan, MSan)
   └─ Grammar-based (if input format is well-defined)

4. RUN (CI or Dedicated)
   └─ Integrate into CI for continuous fuzzing (OSS-Fuzz model)
   └─ Run with sanitizers for maximum bug detection

5. TRIAGE CRASHES
   └─ Deduplicate by stack trace
   └─ Minimize test cases
   └─ Verify exploitability
```

### CI Fuzzing Integration Example (Rust)

```yaml
# .github/workflows/fuzz.yml
name: Fuzz
on: [push, pull_request]
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo install cargo-fuzz
      - run: cargo fuzz run fuzz_target_1 -- -runs=100000
```

---