# FFI Risks — C Interop, bindgen, and libloading Dangers
> **Severity:** High


## Overview

Rust's Foreign Function Interface (FFI) allows calling C libraries and exposing Rust code to C callers. This is a primary source of real-world vulnerabilities because FFI boundaries **bypass Rust's memory safety guarantees**. The C side is unchecked, and the Rust side must manually validate everything crossing the boundary.

## The FFI Threat Model

When Rust interacts with C:
- **C can violate any Rust invariant** — C code can mutate data through aliased pointers, free memory Rust is using, or read past buffer bounds.
- **Rust unsafe code at FFI boundaries** — Every FFI call is inherently `unsafe`. The programmer must ensure safety invariants that the compiler cannot check.
- **ABI mismatches** — Different calling conventions, struct layouts, and alignment expectations cause undefined behavior.
- **Memory ownership confusion** — Who frees what? C allocator (`malloc`) vs. Rust allocator. Mixing them causes corrupt heaps.

## AI/Vibe Coding and FFI

LLMs routinely generate FFI code that:
- Forgets to validate C return values (null pointer checks)
- Passes Rust references to C without ensuring lifetime constraints
- Creates `CString` from untrusted input but then leaks memory or does not handle errors
- Misuses `std::ffi::CStr` and `CString` — panics on interior null bytes or non-UTF8 data

## Vulnerable Code Examples

### Example 1: Null Pointer Dereference via FFI

```rust
use std::ffi::CString;
use std::os::raw::c_char;

extern "C" {
    fn strlen(s: *const c_char) -> usize;
}

// AI-GENERATED — no null check
fn safe_strlen(s: &str) -> usize {
    let c_str = CString::new(s).expect("CString::new failed");
    unsafe { strlen(c_str.as_ptr()) }
}
```

**What could go wrong?** The above is actually safe for this specific call, but AI models typically generate FFI wrappers that *skip the null check on the C return value*. If `strlen` returned a null pointer (in a real scenario with a custom C function), the Rust side would dereference it unsafely.

### Example 2: Incorrect Memory Ownership — Double Free

```rust
use std::ffi::CString;
use std::os::raw::c_char;

extern "C" {
    fn get_config() -> *mut c_char;
    fn free_config(ptr: *mut c_char);
}

// AI-GENERATED — double free risk
fn config() -> String {
    unsafe {
        let ptr = get_config();
        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        // std::mem::drop(s) happens here—OK
        // But CString::from_raw(ptr) would try to free C memory with Rust allocator!
        // If we ran: let _ = CString::from_raw(ptr);
        // THAT would be UB (Rust freeing C memory)
        s
    }
}
```

**Secure Fix**: Follow the C library's allocation contract exactly.

```rust
fn config() -> String {
    unsafe {
        let ptr = get_config();
        if ptr.is_null() {
            return String::new();
        }
        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        free_config(ptr); // Use the C library's own free function
        s
    }
}
```

### Example 3: bindgen Generated Code — Struct Padding Mismatch

```rust
// AI-generated bindgen wrapper with incorrect #[repr(C)] assumptions
#[repr(C)]
struct Packet {
    id: u8,
    data: u32, // Aligned to 4 bytes — padding byte between id and data
}

extern "C" {
    fn process_packet(p: *const Packet);
}
```

**The problem**: C compilers insert padding; Rust's `#[repr(C)]` matches C layout, but AI code often omits `#[repr(C)]` on bindgen-like structs, using default Rust layout which reorders fields for optimization. This causes silent ABI mismatch and UB.

**Secure Fix**: Always use `#[repr(C)]` for FFI structs and verify with `std::mem::offset_of!` tests.

## libloading Dangers

Dynamic library loading (`libloading`) introduces runtime FFI risks:

```rust
// AI-GENERATED — symbol resolution without type safety
let lib = unsafe { Library::new("plugin.so").unwrap() };
let func: unsafe extern "C" fn(*const c_char) -> *mut c_char;
unsafe {
    func = lib.get(b"process\0").unwrap(); // Wrong signature = UB
}
```

**Risks**: No type checking on dynamic symbols. A typo in the symbol name and a wrong function signature both produce UB at runtime. Attackers who can replace the `.so` file (e.g., via `LD_PRELOAD`) gain arbitrary code execution.

## Real CVEs

- **CVE-2024-3094 (xz-utils / liblzma backdoor)**: A malicious maintainer inserted a backdoor into the C library `liblzma`. Any Rust program that links `liblzma` through FFI (e.g. via `lzma-sys`/`xz2`) inherits the compromised C code — the canonical reminder that Rust's safety guarantees stop at the FFI boundary and the C side can do anything. (Not to be confused with CVE-2024-27308, an unrelated `mio` Windows named-pipe use-after-free.)
- **RUSTSEC-2020-0071 / CVE-2020-26235 (`time` crate — C `localtime_r` FFI unsoundness)**: `time` 0.1 and 0.2.7–0.2.22 call C's `localtime_r` while another thread may be mutating the process environment via `setenv`. Because the C library is not thread-safe against concurrent `setenv`, this can dereference a dangling pointer and **segfault** — a genuine memory-safety bug that crosses the Rust↔C boundary. CVSS 6.2. Fixed in 0.2.23. `chrono` had the same class of bug (RUSTSEC-2020-0159).
- **CVE-2022-24713 (`regex` crate — ReDoS)**: Often miscited as an FFI/`rustls` bug; it is actually a pure-Rust ReDoS in the `regex` crate (≤ 1.5.4, fixed 1.5.5) — a crafted regex bypasses the parser's complexity limits. Included here only to correct the misattribution: it is **not** an FFI vulnerability.

## Prevention Checklist

1. **Validate every C pointer** — Check for null before dereferencing.
2. **Use `NonNull<T>`** — For C pointers that are guaranteed non-null.
3. **Never mix allocators** — Rust `Box::from_raw`/`CString::from_raw` can only free memory allocated by Rust's allocator.
4. **Always `#[repr(C)]`** — On structs passed to/from C. Never rely on Rust's default layout.
5. **Wrap FFI in safe APIs** — Expose safe Rust functions that encapsulate `unsafe` FFI calls.
6. **Use `cargo vet` / `cargo crev`** — For third-party crates wrapping C libraries.
7. **Test with sanitizers** — AddressSanitizer (`-Z sanitizer=address`) catches many FFI memory errors.
8. **Pin `bindgen` outputs** — Regenerate bindings only when C headers change; audit diffs.
9. **Validate libloading symbols** — Confirm function signatures match via test harness before production use.
