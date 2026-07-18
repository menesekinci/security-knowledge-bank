---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
heading: "Mistake 1: Using `math/rand` for Security"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [go, hardcoded, language-vuln, mistake, overview, timing-side, using]
chunk: 3/10
---

## Mistake 1: Using `math/rand` for Security

The #1 crypto mistake in AI-generated Go code:

```go
// AI-GENERATED — uses math/rand for tokens (GUARANTEED insecure!)
import "math/rand"

func generateResetToken() string {
    const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    token := make([]byte, 32)
    for i := range token {
        token[i] = charset[rand.Intn(len(charset))] // Predictable!
    }
    return string(token)
}
```

**Why it's broken**: `math/rand` uses a **deterministic PRNG** seeded by a fixed seed (by default, seed = 1 in Go 1.19 and earlier). An attacker who knows the approximate time the server started can predict every "random" value.

**Detection**: 
```bash
# gosec catches math/rand for security contexts
gosec -include G404 ./...
```

**Secure Fix**: Always use `crypto/rand` for secrets.
```go
import "crypto/rand"

func generateResetToken() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}
```