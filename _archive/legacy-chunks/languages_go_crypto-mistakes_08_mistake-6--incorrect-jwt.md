---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
category: "language-vuln"
language: "go"
chunk: 8
total_chunks: 10
heading: "Mistake 6: Incorrect JWT Signing"
---

## Mistake 6: Incorrect JWT Signing

```go
// AI-GENERATED — JWT with "none" algorithm or weak key
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
signedToken, _ := token.SignedString([]byte("weak-key"))

// Or worse: accepts "none" algorithm
// golang-jwt v5 rejects "none" by default, but AI may configure custom validation
```