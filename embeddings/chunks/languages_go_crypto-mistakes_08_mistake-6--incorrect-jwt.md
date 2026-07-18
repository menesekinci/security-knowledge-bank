---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
heading: "Mistake 6: Incorrect JWT Signing"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [go, hardcoded, language-vuln, mistake, overview, timing-side, using]
chunk: 8/10
---

## Mistake 6: Incorrect JWT Signing

```go
// AI-GENERATED — JWT with "none" algorithm or weak key
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
signedToken, _ := token.SignedString([]byte("weak-key"))

// Or worse: accepts "none" algorithm
// golang-jwt v5 rejects "none" by default, but AI may configure custom validation
```