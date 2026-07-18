---
source: "languages/rust/memory-safety-bypasses.md"
title: "Memory Safety Bypasses: transmute, MaybeUninit, mem::forget"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [detection, language-vuln, overview, rust, tools]
---

# Memory Safety Bypasses: transmute, MaybeUninit, mem::forget
> **Severity:** High


## Overview

Rust provides "escape hatches" that intentionally bypass the type system and borrow checker for legitimate low-level programming. However, these same tools are a common source of vulnerabilities — especially in AI-generated code. Three of the most dangerous are:

- **`std::mem::transmute`** — Reinterprets bits of one type as another type
- **`std::mem::MaybeUninit`** — Creates uninitialized memory
- **`std::mem::forget`** — Leaks a value without running its destructor

Each of these is `unsafe` and can produce Undefined Behavior in ways the compiler cannot detect.

## 1. `std::mem::transmute`

`transmute<T, U>(val: T) -> U` tells the compiler to take the bits of `val` and interpret them as type `U`. The compiler trusts that `T` and `U` have the same size and that the reinterpretation is valid.

### AI-Generated Vulnerability

LLMs frequently generate `transmute` for conversions that should use safe alternatives:

```rust
// AI-GENERATED — DANGEROUS: transmute between types with different layouts
fn bytes_to_u32(bytes: [u8; 4]) -> u32 {
    unsafe { std::mem::transmute::<[u8; 4], u32>(bytes) }
}
```

**Problems**:
- **Endianness**: The result differs on big-endian vs. little-endian architectures.
- **Alignment**: `transmute` cannot handle alignment requirements — it may create an improperly aligned reference.
- **Invalid bit patterns**: Transmuting to `bool`, `char`, or `enum` with invalid bit patterns causes UB.

### Secure Alternatives

```rust
// Preferred: explicit byte-order-aware conversion
fn bytes_to_u32(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)  // or from_be_bytes
}

// For reference casting — use pointer casts or `bytemuck` crate
fn cast_slice(bytes: &[u8]) -> &[u32] {
    bytemuck::cast_slice(bytes) // Panics on misalignment, handles padding
}
```

### Real-world impact

Reinterpreting bytes as a richer type without validating them is a recurring source of undefined behavior: transmuting arbitrary bytes into a `bool`, `char`, or `enum` with an out-of-range discriminant is instant UB, and transmuting between references with different lifetimes or aliasing rules can create a use-after-free (see `owning_ref` in the Real CVEs section below). The compiler cannot see any of this — `transmute` explicitly turns off its checks.

## 2. `std::mem::MaybeUninit`

`MaybeUninit<T>` creates a value of type `T` without initializing its memory. Reading an uninitialized value is immediate UB.

### AI-Generated Vulnerability

```rust
// AI-GENERATED — reads uninitialized memory
use std::mem::MaybeUninit;

fn create_array(count: usize) -> Vec<i32> {
    let mut v = Vec::with_capacity(count);
    // BUG: Memory allocated but NOT initialized!
    unsafe {
        v.set_len(count); // Tells Vec it has `count` initialized elements
    }
    v // Reading these elements is UB
}
```

**What happens**: `Vec::set_len` bypasses the normal initialization requirement. An attacker who controls `count` can cause the Vec to expose heap memory contents (information disclosure) or trigger UB when elements are read.

### Secure Fix

```rust
fn create_array(count: usize) -> Vec<i32> {
    (0..count).map(|i| i as i32).collect()
}

// Or for zeroed memory:
let v = vec![0i32; count];

// Or with MaybeUninit done correctly:
let mut v: Vec<MaybeUninit<i32>> = Vec::with_capacity(count);
// ... properly initialize each element before read
unsafe { v.set_len(count); }
// Now transmute to Vec<i32> using assume_init()
```

### The `assume_init()` Danger

```rust
// AI-GENERATED — assumes initialization without proof
let mut x: MaybeUninit<String> = MaybeUninit::uninit();
// Forgot to write anything!
unsafe { x.assume_init() }; // UB — String was never initialized
```

## 3. `std::mem::forget`

`forget(val)` drops the value *without* running its destructor. This is useful for FFI where Rust objects must be owned by C code, but it can also leak resources and break safety invariants.

### AI-Generated Vulnerability

```rust
use std::mem;
use std::sync::Mutex;

// AI-GENERATED — forgets to release a mutex guard
fn critical_section(data: &Mutex<Vec<i32>>) {
    let guard = data.lock().unwrap();
    // Do work...
    mem::forget(guard); // Lock is NEVER released!
    // Other threads deadlock trying to acquire this mutex
}
```

**Worse**: Combined with `ManuallyDrop`, `forget` can cause use-after-free:

```rust
use std::mem::ManuallyDrop;

// AI-GENERATED — double free via forget + manual drop
let s = Box::new(String::from("hello"));
let md = ManuallyDrop::new(s);
// Drop md — nothing happens (ManuallyDrop inhibits drop)
// Later:
drop(md); // Still nothing
// UB if you transmute ManuallyDrop->Box and then drop both
```

### When `forget` Is Actually Needed

FFI ownership transfer is the legitimate use case:
```rust
// Transfer ownership to C — safe because we intend C to free it
let boxed = Box::new(MyCStruct { ... });
let ptr = Box::into_raw(boxed); // Doesn't forget, gives raw ptr
// C code calls a function that consumes ptr
```

## Detection Tools

| Tool | Catches |
|---|---|
| MIRI | `MaybeUninit` reads before init, transmute UB |
| Clippy `clippy::transmute_ptr_to_ref` | Unsafe transmute to reference |
| Clippy `clippy::forget_non_drop` | `forget` on types that don't implement Drop (usually unnecessary) |
| Clippy `clippy::maybe_infinite_value` | Suspect `MaybeUninit` patterns |

## Real CVEs

- **CVE-2020-36317 (`String::retain`, Rust std < 1.49.0)**: If the closure passed to `String::retain` panicked, the string could be left containing non-UTF-8 bytes. Because every other `String`/`str` operation assumes valid UTF-8, this broke a core safety invariant and could lead to memory-safety violations. Fixed in Rust 1.49.0 — a reminder that even the standard library's `unsafe` internals can violate invariants on panic paths.
- **CVE-2021-28875 (`Read::read_to_end`, Rust std < 1.50.0)**: `read_to_end` trusted the byte count returned by a caller-supplied `Read` implementation without validating it. A malicious/buggy `Read` could return a bogus length, driving a buffer overflow in the `unsafe` code that grows the output `Vec`. Fixed in Rust 1.50.0.
- **RUSTSEC-2022-0040 (`owning_ref`)**: `OwningRef::map` / `map_with_owner` and `OwningRefMut::as_owner(_mut)` were unsound and could produce a use-after-free, and the crate violated Rust's aliasing rules (risking miscompilation under LLVM `noalias`). This is the same class of bug as a bad `transmute`: a safe-looking abstraction reinterprets lifetimes/ownership incorrectly. The crate is unmaintained; use `safer_owning_ref` or restructure to avoid self-referential borrows.

## Prevention Checklist

1. **Ban `transmute` in AI-generated code** — Nearly every `transmute` can be replaced with `from_le_bytes`, `bytemuck::cast`, or `From`/`Into` implementations.
2. **Never use `MaybeUninit::assume_init()` without proof** — The safety comment must explain why every byte has been written.
3. **Prefer safe initialization APIs** — `vec![0; n]`, `array::map`, or crate like `arrayvec` over `MaybeUninit`.
4. **Avoid `mem::forget`** — Use `Box::into_raw` / `ManuallyDrop::take` for ownership transfers.
5. **Run MIRI** before merging any code containing these functions.
6. **Use `bytemuck`** for safe byte reinterpretation — it validates alignment, size, and trait bounds.
