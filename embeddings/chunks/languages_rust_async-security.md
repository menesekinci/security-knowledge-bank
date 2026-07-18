---
source: "languages/rust/async-security.md"
title: "🦀 Rust Async Security"
category: "language-vuln"
language: "rust"
severity: "medium"
tags: [async, batbadbut, cve-2024-24576, cve-2025-68260, drop, language-vuln, prevention, rust, rust_binder, rustsec-2020-0124]
---

# 🦀 Rust Async Security
> **Severity:** Medium

## Async Drop Safety

In Rust's async fn's, the `Drop` trait cannot be async. This can lead to async resources (socket, file, lock) not being properly cleaned up when a future is dropped.

## CVE-2024-24576 — BatBadBut (CVSS 10.0)
Command injection in `Command::arg()` and `Command::args()` on Windows.
- `cmd.exe`'s escape mechanism could be bypassed by Rust's default escaping
- Critical when running `.bat`/`.cmd` files
- The highest CVSS CVE in Rust's stdlib in 2024

```rust
// VULNERABLE:
let status = Command::new("cmd")
    .args(&["/C", user_input])  // User input is not escaped!
    .status()?;

// SAFE (Rust 1.77.2+):
// Stdlib now does proper escaping on Windows
```

## CVE-2025-68260 — `rust_binder` `death_list` race (not async UAF)
A race condition in the Rust Binder driver's `death_list` intrusive linked list in the Linux kernel. It is a synchronous concurrency bug, **not** an async/future-cancellation use-after-free and **not** in a network driver.
- The release path drains the shared list into a local list, drops the lock, then mutates node `prev`/`next` pointers that another thread can still be unlinking concurrently
- Data race on the list links → list corruption → kernel oops/panic (local DoS)
- Fixed by processing under the lock; kernel 6.18+ with `CONFIG_ANDROID_BINDER_IPC_RUST=y`. See the concurrency and case-study pages.

## RUSTSEC-2020-0124 — Tokio Data Race
Data race if `tokio::io::AsyncReadExt::read_to_end()` is called from different tasks.

## Prevention
- Pass user input via `Command::arg()`
- Keep Tokio up to date
- Use `tokio::spawn` + cancellation token pattern for async Drop

**Source:**
- CVE-2024-24576: https://nvd.nist.gov/vuln/detail/CVE-2024-24576
- RUSTSEC-2020-0124: https://rustsec.org/advisories/RUSTSEC-2020-0124.html
