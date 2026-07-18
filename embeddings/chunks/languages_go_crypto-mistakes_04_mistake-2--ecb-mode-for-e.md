---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
heading: "Mistake 2: ECB Mode for Encryption"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [go, hardcoded, language-vuln, mistake, overview, timing-side, using]
chunk: 4/10
---

## Mistake 2: ECB Mode for Encryption

```go
// AI-GENERATED — uses ECB mode (broken!)
import "crypto/aes"

func encryptECB(key []byte, plaintext []byte) []byte {
    block, _ := aes.NewCipher(key)
    ciphertext := make([]byte, len(plaintext))
    // BUG: ECB encrypts each 16-byte block independently
    // Identical plaintext blocks produce identical ciphertext blocks
    block.Encrypt(ciphertext, plaintext)
    return ciphertext
}
```

**Why it's broken**: ECB mode leaks data patterns. The famous "ECB penguin" visualization shows that an encrypted image still reveals the underlying structure. In practice, an attacker can identify repeated plaintext blocks and infer message content.

**Secure Fix**: Use AES-GCM (authenticated encryption).
```go
import "crypto/aes"
import "crypto/cipher"

func encryptGCM(key []byte, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, 12)
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    // Seal appends ciphertext+tag to nonce
    ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
    return append(nonce, ciphertext...), nil // Prepend nonce
}
```