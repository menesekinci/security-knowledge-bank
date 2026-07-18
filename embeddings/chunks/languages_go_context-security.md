---
source: "languages/go/context-security.md"
title: "🐹 Go context.Context Security"
category: "language-vuln"
language: "go"
severity: "high"
tags: [common, cve-2025-22869, cve-2025-47914, go, golang, language-vuln, mistakes, prevention, what]
---

# 🐹 Go context.Context Security

## What Is It?
`context.Context` is used in Go for timeout, cancellation, and deadline management. Incorrect usage leads to **goroutine leaks** and **deadline exhaustion**.

## CVE-2025-22869 — golang.org/x/crypto/ssh: memory-exhaustion DoS
Real-world example of what happens when deadline/cancellation is *not* enforced. In `golang.org/x/crypto/ssh`, SSH servers implementing file-transfer protocols read pending content into memory while waiting for the key exchange (KEX) to complete. A client that completes the handshake very slowly — or never — keeps that content buffered but never transmitted, exhausting server memory (DoS). This is a resource-exhaustion bug, not a signature-verification bypass. CVSS 7.5. Fixed in x/crypto 0.35.0. The lesson: bound every handshake with a context deadline so a stalled peer cannot pin resources.

```go
// VULNERABLE — context leak:
func SlowOperation(ctx context.Context) {
    go func() {
        time.Sleep(5 * time.Second)
        // Even if ctx is cancelled, this goroutine lives for 5 more seconds!
        doWork(ctx)
    }()
}

// SAFE:
func SlowOperation(ctx context.Context) {
    go func() {
        select {
        case <-ctx.Done():
            return // Early exit
        case <-time.After(5 * time.Second):
            doWork(ctx)
        }
    }()
}
```

## CVE-2025-47914 — golang.org/x/crypto/ssh/agent: out-of-bounds read DoS
SSH agent servers in `golang.org/x/crypto/ssh/agent` do not validate the size of incoming messages when processing new-identity requests. A malformed message triggers an out-of-bounds read that panics the program (DoS). This is an input-validation/OOB bug, not a context deadline issue — but, like the CVE above, it underscores that long-lived agent/handshake loops must both validate input and be time-bounded. CVSS 5.3. Fixed in x/crypto 0.45.0.

## Common Mistakes
```go
// MISTAKE 1: Passing nil context
func DoSomething(ctx context.Context) {
    if ctx == nil { // context should not be nil!
        ctx = context.Background()
    }
}

// MISTAKE 2: Authentication via key/value in context
ctx = context.WithValue(ctx, "user_id", userInput) // No security check!

// MISTAKE 3: Using context.Background() (no cancel!)
ctx := context.Background() // No timeout/cancel → leak!
```

## Prevention
- Use `context.WithTimeout` or `context.WithCancel` for every long operation
- Wait for cancellation with `select { case <-ctx.Done(): }`
- Use custom types instead of string keys for context values
- Use `context.Background()` only in main/test
- `go vet` catches context errors

**Source:** CVE-2025-22869, CVE-2025-47914
