# Concurrency Issues — Send/Sync Trait Misuse, Data Races in Safe Rust
> **Severity:** High


## The Myth of "Fearless Concurrency"

Rust's concurrency model is often marketed as "fearless concurrency" — the type system prevents data races at compile time. This is **true for safe Rust using standard synchronization primitives**, but it is not the whole story. Several categories of concurrency bugs are **not prevented** by Rust's type system:

1. **Logical race conditions** — The type system does not enforce order of operations
2. **Deadlocks** — No compile-time detection of lock ordering violations
3. **Poisoned mutexes** — Panics in critical sections leave state inconsistent
4. **Send/Sync trait misuse** — Incorrect `unsafe` implementations of these traits cause data races
5. **Atomics misuse** — Wrong memory ordering (`Relaxed` vs. `Acquire`/`Release`) produces subtle bugs

## Send and Sync: The Gateway to Data Races

`Send` and `Sync` are `unsafe` traits that the compiler uses to determine thread safety:

- **`Send`**: A type can be transferred across thread boundaries.
- **`Sync`**: A type can be shared across threads via `&T` (i.e., `&T` is `Send`).

The compiler **automatically** implements these traits for types composed entirely of Send/Sync types. The danger arises when developers **manually** implement them — especially AI-generated code.

### AI-Generated Vulnerability: Incorrect `Sync` Implementation

```rust
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

// AI-GENERATED — attempts to create a "lock-free" type
struct FastCounter {
    value: UnsafeCell<u64>,
    initialized: AtomicBool,
}

// AI assumed UnsafeCell was safe because AtomicBool controls initialization
unsafe impl Sync for FastCounter {}

impl FastCounter {
    fn get(&self) -> u64 {
        // BUG: No synchronization on the read!
        unsafe { *self.value.get() }
    }

    fn increment(&self) {
        unsafe { *self.value.get() += 1; }
    }
}

// DATA RACE: Two threads call increment() simultaneously
static COUNTER: FastCounter = FastCounter {
    value: UnsafeCell::new(0),
    initialized: AtomicBool::new(true),
};

fn main() {
    let t1 = thread::spawn(|| { for _ in 0..1000 { COUNTER.increment(); }});
    let t2 = thread::spawn(|| { for _ in 0..1000 { COUNTER.increment(); }});
}
```

**Why it's wrong**: `UnsafeCell` is `!Sync` by design. Making `FastCounter Sync` tells the compiler it's safe to share `&FastCounter` across threads — but the `get()` and `increment()` methods perform unsynchronized reads/writes on `UnsafeCell<u64>`. This is a **data race** (undefined behavior).

**Secure Fix**: Use `AtomicU64` instead of `UnsafeCell<u64>`, and remove the `unsafe impl Sync`.

```rust
use std::sync::atomic::{AtomicU64, Ordering};

struct FastCounter {
    value: AtomicU64,
}

// AtomicU64 is Sync — no unsafe impl needed
impl FastCounter {
    fn get(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }
    fn increment(&self) {
        self.value.fetch_add(1, Ordering::SeqCst);
    }
}
```

### AI-Generated Vulnerability: Incorrect `Send` Implementation

```rust
use std::rc::Rc;
use std::thread;

// AI-GENERATED — tries to make Rc (non-Send) work across threads
#[derive(Clone)]
struct SharedData {
    data: Rc<Vec<u8>>, // Rc is !Send
}

// BUG: Rc is not thread-safe (non-atomic reference counting)
unsafe impl Send for SharedData {}

let data = SharedData { data: Rc::new(vec![1,2,3]) };
thread::spawn(move || {
    // Thread safety violation: Rc ref-counting is not atomic
    let _ = data;
});
```

**Why it's wrong**: `Rc` uses non-atomic reference counting. Sending it to another thread without `Arc` means the ref-count operations race, leading to double-free or use-after-free.

## Logical Race Conditions (Not Prevented by Type System)

Even in fully safe Rust, **order-of-execution races** are not prevented:

```rust
use std::sync::{Arc, Mutex};
use std::thread;

// AI-GENERATED — race condition in business logic
let shared = Arc::new(Mutex::new(0u64));
let mut handles = vec![];

for _ in 0..10 {
    let shared = Arc::clone(&shared);
    handles.push(thread::spawn(move || {
        let mut val = shared.lock().unwrap();
        // RACE: First thread should initialize, but all 10 may see 0
        if *val == 0 {
            *val = expensive_initialization();
        }
        *val += 1;
    }));
}
```

**Problem**: A check-then-act race — multiple threads may see `*val == 0` and all call `expensive_initialization()`. This is a logic bug (not UB, so Rust doesn't catch it).

## Atomics and Memory Ordering

Misusing memory ordering is a common AI-generated concurrency bug:

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

static READY: AtomicBool = AtomicBool::new(false);
static mut DATA: u64 = 0;

// AI-GENERATED — incorrect memory ordering
fn main() {
    thread::spawn(|| {
        unsafe { DATA = 42; }
        READY.store(true, Ordering::Relaxed); // Wrong! No happens-before
    });

    while !READY.load(Ordering::Relaxed) {} // Spin
    // BUG: DATA may not be 42! The store to DATA may not be visible
    println!("{}", unsafe { DATA });
}
```

**Secure Fix**: Use `Ordering::Release` for store and `Ordering::Acquire` for load (or `Ordering::SeqCst` for simplicity).

```rust
// Writer
unsafe { DATA = 42; }
READY.store(true, Ordering::Release); // All prior writes visible to Acquire

// Reader
while !READY.load(Ordering::Acquire) {} // Sees Release store + all prior writes
```

## Real CVEs

- **CVE-2025-68260 (`rust_binder`, Linux kernel)**: The first CVE in mainline Linux kernel Rust code, and a textbook race. In the `rust_binder` driver, `Node::release` acquired a lock, moved all entries of a doubly-linked `death_list` into a temporary stack list, released the lock, and then traversed the local list. If another thread performed an unsafe removal on the original list in parallel, the concurrent access corrupted the list's `prev`/`next` pointers → memory corruption and a kernel crash (DoS). Fixed in 6.18.1 / 6.19-rc1. Not "Rust failing" — a synchronization/aliasing mistake around an `unsafe` list operation.
- **RUSTSEC-2020-0140 (`model`)**: The crate's `Shared` type implemented `Send`/`Sync` regardless of its inner type, so purely safe code could move a non-thread-safe value across threads and trigger a data race — precisely the manual-`Send`/`Sync` mistake demonstrated above.
- **RUSTSEC-2020-0130 (`bunch`)**: `Bunch<T>` unconditionally implemented `Send`/`Sync`. That let a `T: !Sync` be shared and read from multiple threads via `Bunch::get()`, producing a data race in otherwise-safe code.

## Detection Tools

| Tool | Purpose |
|---|---|
| ThreadSanitizer (TSan) | Dynamic detection of data races | `-Z sanitizer=thread` |
| Loom | Deterministic concurrency testing | `cargo loom` |
| Shuttle | Randomized concurrency testing | `cargo shuttle` |
| Clippy | Lint for atomic ordering, deadlock patterns | `cargo clippy` |

## Prevention Checklist

1. **Never implement `Send` or `Sync` manually** — LLM-generated unsafe trait implementations are almost always wrong. Use `Arc<Mutex<T>>`, `Arc<RwLock<T>>`, or atomics.
2. **Use `loom` for concurrent data structures** — Test all possible interleavings.
3. **Prefer `RwLock` over `Mutex`** for read-heavy workloads (but beware of writer starvation).
4. **Use `parking_lot::Mutex`** — Deadlock detection built in.
5. **Always use `SeqCst` for memory ordering** unless benchmarks prove it's a bottleneck (then use `Acquire`/`Release` with formal review).
6. **Treat `unsafe impl Send/Sync` as code-review red flag** — Require safety comments.
7. **Enable ThreadSanitizer in CI** — Catches races in tests that your type system missed.
