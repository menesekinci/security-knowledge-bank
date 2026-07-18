---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
heading: "Mistake 5: Weak TLS Configuration"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [go, hardcoded, language-vuln, mistake, overview, timing-side, using]
chunk: 7/10
---

## Mistake 5: Weak TLS Configuration

```go
// AI-GENERATED — weak TLS (accepts anything)
server := &http.Server{
    Addr: ":443",
    TLSConfig: &tls.Config{
        InsecureSkipVerify: true, // BUG: Accepts any certificate!
        MinVersion: tls.VersionTLS10, // BUG: Allows TLS 1.0!
        CipherSuites: []uint16{
            tls.TLS_RSA_WITH_RC4_128_SHA, // BUG: RC4!
        },
    },
}
```

**Secure Fix**:
```go
server := &http.Server{
    Addr: ":443",
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        CurvePreferences: []tls.CurveID{
            tls.X25519, tls.CurveP256,
        },
        CipherSuites: []uint16{
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        },
        // Only set InsecureSkipVerify for development
    },
}
```