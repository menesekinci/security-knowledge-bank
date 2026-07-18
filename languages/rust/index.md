# Rust Security Overview: Safety Guarantees vs. Real Risks
> **Severity:** Critical


## Introduction

Rust is widely acclaimed as a "memory-safe" language that eliminates entire classes of vulnerabilities at compile time. Its ownership model, borrow checker, and type system prevent buffer overflows, use-after-free, null pointer dereferencing, and double-free errors that plague C and C++ codebases. However, **Rust is not a security silver bullet**. Real-world Rust code — especially AI/Vibe Coding generated code — regularly introduces vulnerabilities through `unsafe` blocks, unsafe trait implementations, dependency mismanagement, and logic errors that the compiler cannot catch.

## What Rust Guarantees (And What It Doesn't)

### Guarantees (at compile time)
- **No buffer overflows** — Array bounds are checked at runtime; the borrow checker prevents out-of-bounds access via references.
- **No use-after-free** — The borrow checker ensures references never outlive their referent.
- **No null pointer dereferences** — `Option<T>` replaces null; you must handle `None` explicitly.
- **No iterator invalidation** — Shared references to a collection prevent mutation during iteration.
- **No data races** — The `Send` and `Sync` traits ensure that shared mutable state is properly synchronized.

### NOT guaranteed (real risks)
- **Logic errors** — The compiler does not enforce business logic, input validation, or authentication.
- **Denial of service** — No protection against resource exhaustion, unbounded allocations, or algorithmic complexity attacks.
- **Side-channel attacks** — Timing, power, and cache side channels are not prevented by the type system.
- **Unsafe code** — Any `unsafe { }` block disables the borrow checker locally and can introduce all C/C++-style memory bugs.
- **Supply chain** — Crates.io dependencies can introduce malicious code, just like npm or PyPI.
- **Panic safety** — `panic!()` can unwind and leave shared state in an inconsistent state (poisoned mutexes).

## AI/Vibe Coding Creates Rust Vulnerabilities

AI models (LLMs) frequently generate Rust code that compiles but is subtly wrong:

```rust
// AI-generated: assumes split always returns two elements
let parts: Vec<&str> = input.split(':').collect();
// PANIC if input is "abc" — index out of bounds
let name = parts[0];
let value = parts[1];
```

Models default to `unwrap()` and `expect()` constantly, producing code that panics on unexpected input — effectively a DoS vector. They also overuse `unsafe` blocks, implement `Send`/`Sync` incorrectly, and pull in unnecessary dependencies.

## Key Vulnerability Categories in Rust

| Category | Example CVEs | Risk Level |
|---|---|---|
| Concurrency / unsafe misuse | CVE-2025-68260 (rust_binder, Linux kernel) | Critical |
| Supply chain attacks | RUSTSEC-2022-0042 (rustdecimal typo-squat, 2022) | High |
| Panic safety / unwrap | — | Medium |
| Send/Sync violations | RUSTSEC-2020-0140 (model) | High |
| Crypto misuse | CVE-2023-49092 (rsa Marvin timing) | High |
| Async / protocol DoS | CVE-2023-44487 (HTTP/2 Rapid Reset, hyper/h2) | High |

## Real-World CVEs

- **CVE-2025-68260**: First-ever CVE for Rust code in the mainline Linux kernel. Root cause: a race in the `rust_binder` driver's `death_list` handling. `Node::release` moved list entries into a temporary list under a lock, released the lock, then traversed the local list — while another thread could perform an unsafe removal on the original list concurrently, corrupting the doubly-linked list's `prev`/`next` pointers → memory corruption and kernel crash (DoS). Fixed in 6.18.1 / 6.19-rc1.
- **RUSTSEC-2023-0071 / CVE-2023-49092**: `rsa` crate "Marvin Attack" — non-constant-time modular exponentiation leaks timing information that lets an attacker recover the RSA private key by observing decryption/signing time.
- **CVE-2023-44487 (HTTP/2 Rapid Reset)**: Not Rust-specific, but Rust HTTP/2 implementations in `hyper` and `h2` were affected, demonstrating that Rust is not immune to protocol-level DoS.

## Prevention Checklist

1. **Minimize `unsafe`** — Audit every `unsafe` block. Assume LLM-generated `unsafe` is wrong until proven correct.
2. **Replace `unwrap()` with proper error handling** — Use `?`, `Result`, `Option::unwrap_or`, and custom error types.
3. **Run `cargo audit`** — Add to CI to detect known vulnerabilities in dependencies.
4. **Use `cargo deny`** — Block crates with unacceptable licenses or known advisories.
5. **Pin dependency versions** — Use `cargo update` deliberately, not automatically.
6. **Validate all inputs** — Rust does not prevent injection attacks; sanitize user input.
7. **Avoid `unsafe` in AI-generated code** — LLMs frequently produce incorrect unsafe code. Always replace it with safe alternatives.
8. **Use MIRI** — Run `cargo miri` on code containing `unsafe` to detect Undefined Behavior.

## Conclusion

Rust eliminates memory safety bugs in *safe* code, but real-world applications still use `unsafe`, FFI, complex logic, and third-party dependencies. Developers using LLMs for Rust code generation must be especially vigilant: the compiler will catch type errors, but it will not catch logic flaws, panics, or vulnerable `unsafe` patterns. Security in Rust requires discipline beyond what the compiler enforces.
