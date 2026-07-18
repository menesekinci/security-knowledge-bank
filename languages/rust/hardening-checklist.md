# 🦀 Rust Security Hardening Checklist
> **Severity:** High

> Items to check in every Rust project before deployment.

## ✅ General
- [ ] Is `cargo audit` run?
- [ ] Is license + CVE scanning done with `cargo deny`?
- [ ] Is `Cargo.lock` in version control?
- [ ] Is `cargo outdated` run?

## ✅ unsafe
- [ ] Is every `unsafe` block justified?
- [ ] Is the number of `unsafe` blocks minimized?
- [ ] Is there a dangling pointer risk? (functions returning raw pointers)
- [ ] Is `transmute` used? — is there a safe alternative?
- [ ] Is `MaybeUninit` used correctly? (forgotten `assume_init`)
- [ ] Are `mem::forget` / `ManuallyDrop` necessary?

## ✅ Concurrency
- [ ] Are `Send` + `Sync` traits not implemented unsafely? (without justification)
- [ ] Are Mutex/RwLock used? (Are atomics sufficient?)
- [ ] Is `MutexGuard` not leaving scope early?

## ✅ FFI
- [ ] Are `extern "C"` functions marked as `unsafe`?
- [ ] Are pointers from C side null-checked?
- [ ] Is the safety of code produced by `bindgen` checked?
- [ ] If dynamically loading libraries with libloading, is a risk assessment done?

## ✅ Web Framework (Actix/Axum/Rocket)
- [ ] Is CORS configured correctly?
- [ ] Is input validation done? (serde validation)
- [ ] Is stack trace not leaked in error response?
- [ ] Is there rate limiting?

## ✅ Crypto
- [ ] Is `rand` used? — Is `OsRng` or `thread_rng()` sufficient?
- [ ] Is constant-time comparison done? (subtle crate)
- [ ] Is Nonce/IV unique on every use?

## 🛡️ Vibe Coding Extra
- [ ] Are `unsafe` blocks written by AI manually reviewed?
- [ ] Are crates suggested by AI verified?
- [ ] Are AI's Send/Sync implementations justified?
