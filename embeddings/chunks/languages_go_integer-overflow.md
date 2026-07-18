---
source: "languages/go/integer-overflow.md"
title: "Integer Overflow in Go — No Automatic Wrap Protection"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, fixes, go, language-vuln, overflow, problem, secure, vulnerable]
---

# Integer Overflow in Go — No Automatic Wrap Protection

## The Problem

Unlike C/C++ which has undefined behavior on signed overflow, Go defines **wrapping semantics** for signed and unsigned integers. However, this does NOT mean integer overflow is safe — it means the behavior is predictable but **still a security vulnerability**. AI-generated Go code frequently overlooks overflow because "Go handles it."

## How Go Handles Integer Operations

- **Unsigned integers** (`uint`, `uint8`, ..., `uint64`): Wrap around on overflow (modular arithmetic).
- **Signed integers** (`int`, `int8`, ..., `int64`): Also wrap around (two's complement), defined behavior.
- **Go 1.x+ no change**: No built-in overflow checking or trap-on-overflow.

## Why Overflow Is Dangerous

Wrapping arithmetic can produce unexpected results that bypass security checks:

```go
// AI-GENERATED — overflow bypasses balance check
func Withdraw(balance uint64, amount uint64) uint64 {
    if amount <= balance {  // If amount is very large, this could be true
        return balance - amount // But subtraction wraps!
    }
    return 0
}

// Exploit:
// balance = 100, amount = 101 → amount > balance → returns 0 (correct)
// balance = 100, amount = ^uint64(0) → amount (max uint64) > 100 → false
// So the check passes! Then balance - amount = 100 - max = wraps to large number
```

## AI-Generated Vulnerable Patterns

### Pattern 1: Missing Arithmetic Overflow Check

```go
// AI-GENERATED — no overflow protection in auction system
type Bid struct {
    UserID string
    Amount uint64
}

func (a *Auction) PlaceBid(user string, amount uint64) error {
    currentBid := a.CurrentBid
    // Overflow: currentBid + increment can wrap around
    if amount > currentBid {
        a.CurrentBid = amount
        return nil
    }
    return fmt.Errorf("bid too low")
}
```

**Exploit**: Attacker places a bid of `^uint64(0) - 1` (max uint64 minus 1). Since this is larger than any reasonable bid, they win the auction but the system's internal accounting overflows.

### Pattern 2: Loop Counter Overflow

```go
// AI-GENERATED — infinite loop via overflow
func processItems(items []Item) {
    for i := uint8(0); i < uint8(len(items)); i++ {
        // Process item...
    }
}
```

**Problem**: If `len(items)` is 256 or more, the `uint8` counter wraps from 255 to 0, creating an **infinite loop** or **out-of-bounds panic**.

### Pattern 3: Slice/Array Index Overflow

```go
// AI-GENERATED — integer overflow leading to out-of-bounds
func getChunk(data []byte, offset, size uint32) []byte {
    // If offset + size overflows a uint32, this check passes incorrectly
    if offset + size > uint32(len(data)) {
        return nil
    }
    return data[offset:offset+size] // But offset+size overflowed!
}
```

**Exploit**: `offset = 0xFFFFFFF0`, `size = 0x00000020`. Sum = `0x100000010` → truncated to `0x00000010` (assuming overflow). The check passes because `0x10 <= len(data)`, but the intended range was beyond the buffer.

### Pattern 4: Monetary Calculations

```go
// AI-GENERATED — money calculation with overflow
func calculateTotal(items []struct{ Price uint64; Quantity uint32 }) uint64 {
    var total uint64
    for _, item := range items {
        total += item.Price * uint64(item.Quantity) // Overflow possible!
    }
    return total
}
```

**Exploit**: A single item with `Price = 2^32` and `Quantity = 2^32` multiplies to `2^64`, which wraps to 0. Customer buys expensive items for free.

## Secure Fixes

### Use Safe Arithmetic Functions

`math/bits` (available since Go 1.9) provides primitives for overflow-safe operations:

```go
import "math/bits"

// Safe addition
func safeAdd(a, b uint64) (uint64, bool) {
    sum, carry := bits.Add64(a, b, 0)
    return sum, carry != 0 // carry != 0 means overflow
}

// Usage
func (a *Auction) PlaceBid(user string, amount uint64) error {
    newBid, overflow := safeAdd(a.CurrentBid, amount)
    if overflow {
        return fmt.Errorf("overflow detected")
    }
    a.CurrentBid = newBid
    return nil
}
```

### Pattern-Specific Fixes

```go
// FIX for slice offset: check before addition
func getChunk(data []byte, offset, size uint64) ([]byte, error) {
    if size > math.MaxInt64 - offset { // Check for overflow
        return nil, fmt.Errorf("overflow")
    }
    end := offset + size
    if end > uint64(len(data)) {
        return nil, fmt.Errorf("out of bounds")
    }
    return data[offset:end], nil
}

// FIX for money: use a checked math package or big integers
import "math/big"

func calculateTotal(items []struct{ Price uint64; Quantity uint32 }) *big.Int {
    total := new(big.Int)
    for _, item := range items {
        price := new(big.Int).SetUint64(item.Price)
        quantity := new(big.Int).SetUint64(uint64(item.Quantity))
        itemTotal := new(big.Int).Mul(price, quantity)
        total.Add(total, itemTotal)
    }
    return total
}
```

### Use Third-Party SafeMath Libraries

```go
import "github.com/cosmos/cosmos-sdk/types"

// Cosmos SDK's Uint type uses checked arithmetic
a := types.NewUintFromString("100")
b := types.NewUintFromString("200")
sum, err := a.Add(b) // Returns error on overflow
```

## Real CVEs

- **CVE-2023-24537 (go/scanner, CVSS 7.5)**: A textbook **integer overflow** (CWE-190). Parsing Go source that contains `//line` directives with very large line numbers overflowed the line-number arithmetic in `Scanner.updateLineInfo`, sending the scanner into an **infinite loop** — a denial of service reachable by any tool that parses untrusted Go source. Fixed in Go 1.19.8 and 1.20.3.
- **CVE-2021-38297 (Go wasm runtime, CVSS 9.8 Critical)**: When Go is compiled to WebAssembly (`GOARCH=wasm GOOS=js`), the size of arguments passed into a module function invocation was computed **without overflow checking**, so sufficiently large arguments overflowed the length calculation and produced a **buffer overflow** — the canonical "integer overflow in a size computation feeds an out-of-bounds write" pattern. Fixed in Go 1.16.9 and 1.17.2.

## Prevention Checklist

1. **Use `math/bits` for overflow-checked arithmetic** in all security-critical calculations.
2. **Avoid small integer types** (`uint8`, `int8`, `uint16`) for counters that could realistically exceed their range.
3. **Use `big.Int` for money/currency** — Never use integer types for financial calculations.
4. **Check before adding** — `if b > MaxVal - a { overflow }` pattern.
5. **Use the `safe` method** — Go 1.21+ `slices` package uses safe bounds automatically.
6. **Run `staticcheck`** — Flags some potential overflow patterns (`SA1009`, `SA1011`).
7. **Test with extreme values** — `math.MaxUint64`, `math.MaxInt64` as inputs in tests.
8. **Prefer `int` over `int32`/`int64`** — On 64-bit platforms, `int` is 64-bit, reducing overflow probability (but not eliminating it).
