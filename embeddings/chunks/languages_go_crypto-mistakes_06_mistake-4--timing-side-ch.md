---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
heading: "Mistake 4: Timing-Side Channel in Comparison"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [go, hardcoded, language-vuln, mistake, overview, timing-side, using]
chunk: 6/10
---

## Mistake 4: Timing-Side Channel in Comparison

```go
// AI-GENERATED — non-constant-time comparison for HMAC
func verifyMAC(message, key, expectedMAC []byte) bool {
    mac := computeHMAC(message, key)
    return string(mac) == string(expectedMAC) // Timing leak!
}
```

**Secure Fix**: Use constant-time comparison.
```go
import "crypto/subtle"

func verifyMAC(message, key, expectedMAC []byte) bool {
    mac := computeHMAC(message, key)
    return subtle.ConstantTimeCompare(mac, expectedMAC) == 1
}
```

`crypto/subtle` also provides:
- `ConstantTimeSelect(v, x, y int)` — Branch-free conditional
- `ConstantTimeEq(x, y int)` — Branch-free equality check
- `ConstantTimeByteEq(x, y uint8)` — Per-byte comparison