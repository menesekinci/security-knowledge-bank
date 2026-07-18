---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
category: "language-vuln"
language: "go"
chunk: 5
total_chunks: 10
heading: "Mistake 3: Hardcoded Encryption Keys"
---

## Mistake 3: Hardcoded Encryption Keys

```go
// AI-GENERATED — hardcoded encryption key (and it's weak!)
const encryptionKey = "my-secret-key-123" // Only 16 chars, low entropy

func encrypt(data []byte) []byte {
    // Uses constant key...
}
```

**Secure Fix**: Derive keys from a passphrase using a KDF, or fetch from env/secrets manager.
```go
import "golang.org/x/crypto/pbkdf2"

func deriveKey(passphrase string, salt []byte) []byte {
    return pbkdf2.Key([]byte(passphrase), salt, 600000, 32, sha256.New)
}

// Key comes from environment or vault, never code:
key := []byte(os.Getenv("ENCRYPTION_KEY"))
```