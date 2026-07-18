---
source: "languages/rust/rust-ffi-deep.md"
title: "🦀 Rust FFI Deep Dive"
category: "language-vuln"
language: "rust"
severity: "medium"
tags: [callback, cve-2020-26235, language-vuln, mitigation, rust, rustsec-2020-0071, safety]
---

# 🦀 Rust FFI Deep Dive
> **Severity:** Medium


## C Callback Safety
When passing a callback from Rust into C code:
- What is on the Rust stack at the moment the C code invokes the callback?
- Does a panic propagate into C? (undefined behavior!)

```rust
// VULNERABLE:
extern "C" fn callback(data: *mut c_void) {
    // panic!() → propagates into the C stack → UB!
}

// SECURE:
extern "C" fn callback(data: *mut c_void) {
    let result = std::panic::catch_unwind(|| {
        // panic does not propagate into C
    });
}
```

## UB via setjmp/longjmp
If the C code uses `setjmp`/`longjmp`, the Rust stack frame is skipped — drop does not run, and resources leak.

## RUSTSEC-2020-0071 / CVE-2020-26235 — `time` crate: C `localtime_r` FFI segfault
A real Rust↔C FFI memory-safety bug. The `time` crate (0.1, 0.2.7–0.2.22) calls C's `localtime_r` while another thread may mutate the process environment via `setenv`. The C runtime is not thread-safe against concurrent `setenv`, so the call can dereference a dangling pointer and **segfault** — Rust's guarantees end where the C call begins. CVSS 6.2. Fixed in 0.2.23; `chrono` shared the same class of bug (RUSTSEC-2020-0159). This is why FFI wrappers around non-thread-safe C functions must document and enforce the C library's threading contract.

> Note: CVE-2025-68260 (Linux kernel `rust_binder` `death_list` race) is sometimes cited as an "FFI" bug, but it is a **pure-Rust concurrency** bug with no C/Rust FFI boundary involved — it does not belong in an FFI discussion.

## Mitigation
- Wrap everything in `extern "C"` callbacks with `catch_unwind`
- Verify that the C code does not use setjmp/longjmp
- Manage the lifetime of the pointers you pass to C (do not create zombie pointers)
- Use the `Pin` + `Box::into_raw` + guaranteed cleanup pattern

**Source:** RUSTSEC-2020-0071 / CVE-2020-26235
