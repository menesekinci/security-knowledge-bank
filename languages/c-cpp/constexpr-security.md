# 🔴 C++ constexpr / Compile-Time Evaluation Security

## What Is It?

`constexpr` introduced with C++11 and expanded in C++14/17/20 enables **compile-time** computation. C++20's `consteval` requires **strictly compile-time** execution.

These features have two security implications:
1. **Side effects**: constexpr functions can also run at runtime — leading to unexpected behavior
2. **Compile-time bombs**: Infinite loops, heap exhaustion, or DoS via template metaprogramming during compilation

## How Does It Appear in Vibe Coding?

```
Prompt: "Write a hash function, performance is important"
AI: "Writes a constexpr compile-time hash function.
     But does not check for hash collisions and contains UB!"
```

## 1. constexpr Evaluation Security Risks

### UB Not Caught in constexpr

```cpp
// 💀 DANGEROUS — UB disguised as constexpr
constexpr int divide(int a, int b) {
    return a / b;  // if b=0 it's UB — but you get a compile error in constexpr
}

// If called at runtime:
int x = divide(10, 0);  // UB! — constexpr doesn't run at compile-time, crash at runtime
```

**Source:** https://herbsutter.com/2025/03/ - Herb Sutter's constexpr analysis

### Dual Behavior of constexpr Functions

```cpp
// 💀 constexpr function — compile-time or runtime
constexpr int processInput(int x) {
    // This function can run BOTH at compile-time AND runtime
    volatile int sideEffect = x;  // volatile doesn't work at compile-time in constexpr!
    return x * 2;
}

// Compile-time:
constexpr int a = processInput(5);  // ✅ — compile-time

// Runtime:
int b = processInput(userInput);     // runtime — volatile works
```

### Compile-Time Heap Exhaustion

```cpp
// 💀 DANGEROUS — Compile-time heap exhaustion
template<size_t N>
struct Exploit {
    char data[N];  // As N grows, compile-time memory consumption increases
    static constexpr size_t size = N;
};

// Compiler crash
constexpr auto huge = Exploit<1000000000>();  // Compile-time OOM
```

## 2. Compile-Time Side Channels with constexpr

During constexpr evaluation, compiler optimizations can leak information:

```cpp
// 💀 Potential side channel
constexpr bool constantTimeCompare(const char* a, const char* b, size_t len) {
    // constexpr compiler optimization:
    // Stops at the first differing byte — may be vulnerable to timing attacks
    for (size_t i = 0; i < len; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}
```

## 3. metafunction / Template Metaprogramming Exploits

### Compile-Time Recursive Bomb

```cpp
// 💀 Compile-time recursion bomb
template<int N>
struct Fibonacci {
    static constexpr int value = Fibonacci<N-1>::value + Fibonacci<N-2>::value;
    // Note: template instantiations are MEMOIZED — Fibonacci<N> instantiates
    // only ~N distinct specializations, NOT billions. The real bug here is that
    // Fibonacci<50> = 12,586,269,025 overflows a 32-bit `int` (max 2,147,483,647).
};

template<>
struct Fibonacci<0> { static constexpr int value = 0; };

template<>
struct Fibonacci<1> { static constexpr int value = 1; };

// constexpr auto fib = Fibonacci<50>::value;  // Signed-integer overflow (UB)!
```

The genuine compile-time DoS risk is **deep or unmemoizable recursion** (e.g. recursion whose template argument grows without bound, or huge `char[N]` arrays), which consumes compiler memory/time to **stall the compilation process** — a possible software supply chain attack vector.

### Stateful Metaprogramming (C++20)

```cpp
// ❌ This does NOT work — a mutable static local is not a constant expression,
//    so it cannot be read/modified inside a consteval/constexpr evaluation:
// consteval int get_id() { static int counter = 0; return counter++; }  // compile error

// 💀 Real C++ stateful metaprogramming abuses FRIEND-FUNCTION INJECTION:
// each template instantiation defines a new friend, and an unqualified
// (ADL) lookup "reads" how many have been defined so far — giving the
// compiler a hidden, order-dependent counter with no static local at all.
template<int N> struct reader { friend auto flag(reader<N>); };
template<int N> struct setter { friend auto flag(reader<N>) {} static constexpr int value = N; };

// Instantiating `setter<N>` DEFINES the friend for slot N; a later
// `flag(reader<N>)` lookup succeeds only if that slot was already set —
// so the observable count depends on template-instantiation ORDER, which
// is exactly why it is dangerous (fragile, ODR-hostile, a compile-time
// DoS/obfuscation vector).
```

**Source:** https://mc-deltat.github.io/articles/stateful-metaprogramming-cpp20

## 4. constexpr String Hashing & Hash Collision DoS

```cpp
// 💀 constexpr hash function — vulnerable to collision attack
constexpr size_t fast_hash(const char* str) {
    size_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;  // djb2
    }
    return hash;
}

// If an attacker sends thousands of strings with the same hash value
// it leads to unordered_map O(n²) behavior (HashDoS)
```

## Prevention Methods

```cpp
// ✅ SAFE — memory limit in constexpr
template<size_t MaxSize = 1024>
struct SafeBuffer {
    static_assert(MaxSize <= 1024, "Buffer too large for compile-time");
    char data[MaxSize];
};

// ✅ SAFE — base cases stop the recursion, bounds guard depth & overflow
template<int N>
struct SafeFibonacci {
    static_assert(N >= 0,  "N must be non-negative");
    static_assert(N <= 40, "Too deep for compile-time evaluation");
    // long long avoids the 32-bit overflow seen with Fibonacci<50> above
    static constexpr long long value =
        SafeFibonacci<N-1>::value + SafeFibonacci<N-2>::value;
};

// Base cases — without these the template recurses forever into negative N
template<> struct SafeFibonacci<0> { static constexpr long long value = 0; };
template<> struct SafeFibonacci<1> { static constexpr long long value = 1; };

// ✅ SAFE — runtime fallback for constexpr
constexpr int safe_divide(int a, int b) {
    if (b == 0) return 0;  // Prevent UB
    return a / b;
}
```

## References

- https://herbsutter.com/2025/03/
- https://blog.trailofbits.com/2019/06/27/use-constexpr-for-faster-smaller-and-safer-code/
- https://pvs-studio.com/en/blog/posts/cpp/0909/
- https://mc-deltat.github.io/articles/stateful-metaprogramming-cpp20
- https://stackoverflow.com/questions/52078752/how-to-tell-if-constexpr-is-evaluated-at-compile-time-without-manual-inspecti
