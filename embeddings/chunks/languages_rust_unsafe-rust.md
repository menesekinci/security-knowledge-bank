---
source: "languages/rust/unsafe-rust.md"
title: "Unsafe Rust: `unsafe { }` Pitfalls — Dangling Pointers, UB, and FFI"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [code, cves, detection, language-vuln, real, rust, tools, vulnerable, what]
---

# Unsafe Rust: `unsafe { }` Pitfalls — Dangling Pointers, UB, and FFI
> **Severity:** High


## What Is `unsafe` in Rust?

The `unsafe` keyword enables five superpowers that the borrow checker normally prohibits:

1. **Dereference a raw pointer** (`*const T`, `*mut T`)
2. **Call an unsafe function** (including FFI/extern functions)
3. **Access or modify a mutable static variable**
4. **Implement an unsafe trait** (e.g., `Send`, `Sync`)
5. **Access fields of `union` types**

The contract of `unsafe` is that **the programmer is responsible for upholding Rust's safety guarantees**. If you break them, the result is **Undefined Behavior (UB)** — the compiler may generate any code, including code that corrupts memory, leaks secrets, or creates exploitable vulnerabilities.

## Why AI/Vibe Coding Produces Dangerous Unsafe Code

LLMs lack deep reasoning about pointer provenance, aliasing rules, and memory layout. They frequently generate `unsafe` code that:

- **Creates dangling pointers** — returning references to stack-local data
- **Violates pointer aliasing rules** — creating `&mut` and `&` to the same memory simultaneously
- **Misuses `std::mem::transmute`** — reinterpreting types in violation of layout guarantees
- **Manually implements `Drop` incorrectly** — double-free or use-after-free via `ManuallyDrop`

## Vulnerable Code Examples

### Example 1: Dangling Pointer via AI-Generated Unsafe

```rust
// AI-GENERATED — DO NOT USE
fn get_ref<'a>(ptr: *const i32) -> &'a i32 {
    unsafe { &*ptr }  // Dangling if ptr is invalid!
}

fn main() {
    let r;
    {
        let x = 42;
        r = get_ref(&x as *const i32);
    } // x dropped here — r now dangling
    println!("{}", *r); // UB — use after drop
}
```

**Why it's wrong**: The borrow checker cannot track raw pointer lifetimes. The `unsafe` block creates a reference from a pointer that outlives its referent.

**Secure Fix**:
```rust
fn get_ref(x: &i32) -> &i32 {
    x  // Safe — borrow checker ensures lifetime validity
}
```

### Example 2: Incorrect `unsafe` Trait Implementation

```rust
// AI-GENERATED — Unsound Send/Sync implementation
use std::cell::UnsafeCell;
use std::thread;

struct SharedData {
    data: UnsafeCell<i32>,
}

// AI incorrectly assumed this was safe because UnsafeCell is !Sync by default
unsafe impl Sync for SharedData {}

// Now multiple threads can concurrently mutate via Shared references — data race!
static SHARED: SharedData = SharedData { data: UnsafeCell::new(0) };
```

**Why it's wrong**: `Sync` means "safe to share across threads." `UnsafeCell` is deliberately `!Sync` because interior mutability without synchronization causes data races. Making it `Sync` is UB.

**Secure Fix**: Use `Mutex`, `RwLock`, or `atomic` types for shared mutable state.

```rust
use std::sync::Mutex;
struct SharedData {
    data: Mutex<i32>,
}
// Safe: Mutex<T> is Sync when T is Send
```

### Example 3: Incorrect Raw Pointer Arithmetic

```rust
// AI-GENERATED — assumes contiguous allocation
fn process_slice(ptr: *const i32, len: usize) {
    for i in 0..len {
        unsafe {
            let val = *ptr.add(i); // UB if allocation isn't contiguous or out of bounds!
            println!("{}", val);
        }
    }
}
```

**Secure Fix**: Use safe slice indexing.
```rust
fn process_slice(slice: &[i32]) {
    for (i, val) in slice.iter().enumerate() {
        println!("{val}");
    }
}
```

## Real CVEs Involving Unsafe Rust

- **CVE-2021-28879 (Rust standard library — `Zip` iterator)**: In `std` before Rust 1.52.0, the `Zip` iterator's `unsafe` specialization could report an incorrect size due to an integer overflow, leading to a **buffer overflow** when a partially-consumed `Zip` iterator is reused. A genuine break of Rust's memory-safety guarantee inside the standard library's own `unsafe` code. Fixed in 1.52.0. (It is a `std` bug, not a `rustc`/`TyCtxt` bug.)
- **CVE-2021-31162 (Rust standard library — `Vec::from_iter`)**: Also in `std` before 1.52.0, a **double free** occurs in the `Vec::from_iter` specialization if dropping an element panics — the `unsafe` cleanup path frees the same allocation twice. Fixed in 1.52.0.
- **CVE-2025-68260 (Linux kernel `rust_binder`)**: A **race condition** on the `death_list` intrusive linked list — two threads mutate the list's prev/next pointers in parallel inside an `unsafe` block whose aliasing invariant was violated — causing a kernel oops/panic (local DoS). It is a concurrency/aliasing bug, not a "network use-after-free." First CVE against Rust code in the mainline Linux kernel.

## Detection Tools

| Tool | Purpose | Command |
|---|---|---|
| MIRI | Interpreter that detects UB in unsafe code | `cargo +nightly miri test` |
| Loom | Concurrency UB detection | `cargo loom` |
| Sanitizers | ASan, TSan, MSan for Rust | `RUSTFLAGS="-Z sanitizer=address"` |
| Clippy | Lints for common unsafe pitfalls | `cargo clippy -- -W clippy::pedantic` |

## Prevention Checklist

1. **Never trust AI-generated `unsafe` code** — Treat it as a starting point for manual review, never as production-ready.
2. **Add safety invariants as comments** — Every `unsafe` block must explain *why* it's safe (the "Safety" section convention).
3. **Prefer safe abstractions** — `std::sync::Arc`, `std::cell::RefCell`, `slice::get()` over raw pointer manipulation.
4. **Run MIRI on CI** — Catches UB that the compiler silently accepts.
5. **Minimize `unsafe` surface area** — Encapsulate unsafe code in small, auditable safe wrappers.
6. **Audit all `unsafe trait` implementations** — `Send`, `Sync`, `Index`, `IndexMut` implemented incorrectly are undefined behavior.
