# 🦀 Rust Pin Safety & Self-Referential Structs
> **Severity:** High


### What Is It?
The Pin API exists to guarantee the safety of **self-referential structs** in Rust. If a struct holds a pointer to one of its own fields, it must not be moved. Pin provides that guarantee.

## RUSTSEC-2023-0070 — self_cell covariance unsoundness
`self_cell` builds self-referential structs (a value plus a borrow into that same value — the exact pattern `Pin` exists to make safe). Affected versions did an insufficient covariance check, letting a dependent type that is actually *invariant* (e.g. `RefCell<Box<dyn Display + 'a>>`) be treated as covariant. That allowed undefined behavior from purely safe code. Fixed in 0.10.3 / 1.0.2, which now reject such types at compile time.

## RUSTSEC-2019-0020 — generator unsound APIs
The `generator` crate implements stackful coroutines — inherently self-referential, movement-sensitive state that `Pin` is meant to protect. Affected versions exposed APIs that could read uninitialized memory (e.g. when used outside a generator context), leading to undefined behavior. Fixed by tightening the unsafe API surface.

> Note: CVE-2025-68260 (the first Linux-kernel Rust CVE) is sometimes mislabeled as a Pin/async bug — it is actually a `rust_binder` `death_list` race condition leading to memory corruption and DoS, not a Pin-contract violation. See the concurrency page.

## Common Pin Mistakes
```rust
// MISTAKE: mutating the value inside Pin<Box<T>>
let pinned = Box::pin(MyStruct { data: 42 });
// pinned.as_mut().get_mut().data = 43; // doesn't MOVE, but still!

// CORRECT: with Pin<&mut T>
fn process(pinned: Pin<&mut MyStruct>) {
    // pin projection must be unsafe
    unsafe { pinned.get_unchecked_mut().data = 43; }
}
```

## Protection
- Verify the safety invariants in `unsafe` pin projections
- Use the `pin-project` crate (safe pin projection)
- Test future-cancellation cases (with tokio::select!)

**Source:** RUSTSEC-2023-0070, RUSTSEC-2019-0020
