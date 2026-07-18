---
source: "languages/go/index.md"
title: "Go Security Overview: Safety, Risks, and Common Vulnerabilities"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [cves, go, introduction, language-vuln, real-world, vulnerability, what]
---

# Go Security Overview: Safety, Risks, and Common Vulnerabilities

## Introduction

Go (Golang) is a statically typed, compiled language designed at Google for building scalable, networked services. Its design philosophy emphasizes simplicity, readability, and built-in concurrency. Go provides memory safety through garbage collection (eliminating use-after-free and buffer overflow bugs), a strong type system, and standard library defaults that favor security (e.g., `html/template` auto-escapes output, `crypto/rand` uses OS entropy).

However, Go's security guarantees have important gaps that AI/Vibe Coding generated code frequently exploits. Go does **not** protect against:

- **Integer overflow** — Wrapping behavior differs by operation type
- **Logic errors** — No enforcement of business rules or access control
- **Concurrency races** — The type system does not prevent data races (unlike Rust)
- **Injection attacks** — SQL injection, command injection, template injection are all possible
- **Panic-based DoS** — Unrecovered panics crash the server

## What Go Does Well for Security

- **Memory safety** — GC prevents use-after-free, buffer overflows, double-free
- **No pointer arithmetic** — Cannot forge pointers or iterate past array bounds
- **Goroutine stack safety** — Stacks grow dynamically, no stack buffer overflows
- **`html/template` context-aware escaping** — Auto-escapes based on HTML/JS/CSS context
- **Built-in crypto** — `crypto/rand`, `crypto/tls`, `golang.org/x/crypto` are well-maintained
- **Fast compilation** — Encourages frequent testing and static analysis
- **`go vet` and staticcheck** — Catch many common bugs at analysis time

## The AI/Vibe Coding Problem in Go

LLMs generate Go code that compiles successfully but contains security flaws for several reasons:

1. **Go's simplicity is deceptive** — AI models write code that "looks right" but has subtle logic errors
2. **Error handling is verbose** — AI shortcuts by using `_` to discard errors
3. **Concurrency is easy to write, hard to get right** — Goroutines + shared memory = races
4. **Default HTTP server is production-ready but needs hardening** — AI omits timeouts, TLS config, rate limiting
5. **`interface{}` / `any` bypasses type safety** — AI uses interface{} for generic-style code, losing compile-time checks

## Key Vulnerability Categories in Go

| Category | Severity | AI Generation Frequency |
|---|---|---|
| SQL injection | Critical | Very High — AI writes raw SQL without parameterization |
| Data races | High | High — AI adds goroutines without synchronization |
| Integer overflow | Medium | High — AI assumes int is "big enough" |
| SSRF | High | High — AI makes HTTP calls to user-supplied URLs |
| Template injection (text/template) | Critical | Medium — AI uses text/template for HTML |
| Panic/recover misuse | Medium | Medium — AI uses recover() incorrectly, letting panics propagate |
| Crypto misuse | High | Medium — AI uses math/rand for security, weak hashes |
| Supply chain | High | Low-Medium — AI adds unvetted modules from `go get` |

## Real-World CVEs

- **CVE-2024-44905**: SQL injection in `go-pg` ORM via the `/types/append_value.go` component — demonstrates that even popular Go ORMs can have injection flaws.
- **CVE-2024-34156 (encoding/gob, stdlib)**: Denial of service via stack exhaustion. Calling `Decoder.Decode` on a message containing deeply nested structures panics the process. CVSS 7.5. Fixed in Go 1.22.7 / 1.23.1.
- **CVE-2023-45142 (opentelemetry-go-contrib / otelhttp)**: Denial of service via unbounded metric cardinality. The instrumentation wrapper records HTTP labels (e.g. method, User-Agent) with no cardinality limit, so attacker-randomized values exhaust server memory. CVSS 7.5. Fixed in v0.44.0.
- **CVE-2023-39326 (net/http, stdlib)**: A malicious sender can abuse HTTP chunk extensions in chunked request bodies to make the server read far more network bytes than the body contains (up to ~1 GiB), causing memory-based DoS. CVSS 5.3. Fixed in Go 1.20.12 / 1.21.5.
- **CVE-2023-24532 (crypto/internal/nistec, stdlib)**: The P-256 `ScalarMult`/`ScalarBaseMult` methods may return an **incorrect result** for certain unreduced scalars (larger than the curve order) — a correctness bug, not a timing side channel. CVSS 5.3. Fixed in Go 1.19.7 / 1.20.2.

## Prevention Checklist

1. **Never discard errors** — Always handle `error` returns. Use `defer` for cleanup.
2. **Always parameterize SQL** — Use `?` placeholders with `database/sql`. Never use `fmt.Sprintf` for SQL.
3. **Always use `crypto/rand` for secrets** — Never `math/rand` for tokens, passwords, or keys.
4. **Always set HTTP timeouts** — `http.Server{ReadTimeout, WriteTimeout, IdleTimeout}`.
5. **Always validate redirects** — `http.Client{CheckRedirect}` to prevent open redirects and SSRF.
6. **Use `go vet`, `staticcheck`, and `gosec`** — In CI pipeline.
7. **Pin module versions** — Use `go mod verify` and `go.sum` integrity checking.
8. **Use `html/template` for HTML** — Never `text/template` for user-facing HTML output.
9. **Run the race detector** — `go test -race` catches data races before production.
10. **Review all `go:linkname` and `unsafe`** — These bypass Go's safety guarantees.

## Conclusion

Go eliminates memory corruption bugs but leaves developers exposed to logic bugs, injection attacks, concurrency races, and crypto misuse — the very vulnerabilities that AI-generated code introduces most frequently. A security-conscious Go developer treats Go's safety guarantees as a baseline, not a fortress.
