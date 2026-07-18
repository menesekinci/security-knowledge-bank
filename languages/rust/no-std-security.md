# 🦀 Rust no_std & Embedded Security
> **Severity:** Medium

## What Is It?
Embedded Rust (`no_std`) runs without allocator and OS support. No heap allocation, stack limited, panic = halt.

## RUSTSEC-2021-0003 / CVE-2021-25900 — smallvec Heap Buffer Overflow
`SmallVec::insert_many` allocated a buffer smaller than needed and then wrote past its end, corrupting the heap. It triggered whenever the passed iterator yielded more items than the lower bound reported by its `size_hint`. `smallvec` is `no_std`-compatible and heavily used on embedded targets, so on firmware that enables a heap this is a direct memory-corruption primitive — and with no OS/MMU there is no process boundary to contain it. Fixed in 0.6.14 and 1.6.1.

```rust
// VULNERABLE no_std allocator:
#[global_allocator]
static ALLOC: DummyAllocator = DummyAllocator;
// A heap overflow like RUSTSEC-2021-0003 corrupts adjacent allocations;
// with no memory protection, this is UB that can brick or hijack the device.
```

## no_std Specific Risks
- **Panic = Halt**: A panic stops the entire system (no recovery)
- **Stack overflow**: Unprotected, UB if overflowed
- **Allocator safety**: If using heap, the allocator itself can be a vulnerability
- **Watchdog timer**: Don't forget to feed the watchdog during critical operations

## Prevention
- Use `panic-abort` instead of `panic-halt` (triggers reset, safer)
- Analyze stack usage with `stack-sizes`
- Leave a stack guard at the `cortex-m-rt` entry point
- Check for double-free, use-after-free in allocator implementation

**Source:** RUSTSEC-2021-0003, CVE-2021-25900
