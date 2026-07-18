# Crypto Mistakes — Go Crypto Library Misuse

## Overview

Go's standard library provides excellent cryptographic primitives (`crypto/aes`, `crypto/rsa`, `crypto/tls`, `golang.org/x/crypto`). However, the APIs are low-level and easy to misuse. AI-generated Go crypto code consistently makes the same mistakes: using `math/rand` for secrets, ECB mode for encryption, hardcoded keys, and incorrect nonce handling.

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

## Mistake 6: Incorrect JWT Signing

```go
// AI-GENERATED — JWT with "none" algorithm or weak key
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
signedToken, _ := token.SignedString([]byte("weak-key"))

// Or worse: accepts "none" algorithm
// golang-jwt v5 rejects "none" by default, but AI may configure custom validation
```

## Real CVEs

- **CVE-2023-24532 (crypto/internal/nistec, CVSS 5.3)**: The P-256 curve's `ScalarMult` and `ScalarBaseMult` methods returned an **incorrect result** (not a timing leak) when called with certain unreduced scalars larger than the order of the curve. This is a CWE-682 "incorrect calculation" bug; it did **not** affect `crypto/ecdsa` or `crypto/ecdh`, only direct users of the internal nistec package. Fixed in Go 1.19.7 and 1.20.2.
- **CVE-2024-45337 (golang.org/x/crypto/ssh, CVSS 9.1 Critical)**: An **authorization bypass** caused by applications misusing `ServerConfig.PublicKeyCallback`. Because the SSH protocol lets a client offer several public keys before proving ownership of any, an app that makes authorization decisions from a key other than the one finally authenticated could authorize the wrong identity. The fix guarantees the last key passed to the callback is the authenticated one. Fixed in x/crypto 0.31.0.
- **CVE-2025-22869 (golang.org/x/crypto/ssh, CVSS 7.5)**: A **denial of service** in the SSH server: a client that delays or never completes the key exchange makes the server accumulate unsent data in memory, exhausting resources. Fixed in x/crypto 0.35.0.

## Prevention Checklist

1. **Always use `crypto/rand` for secrets** — Never `math/rand`. `gosec G404` catches this.
2. **Always use authenticated encryption** — AES-GCM or ChaCha20-Poly1305, never ECB/CBC alone.
3. **Always use `crypto/subtle.ConstantTimeCompare`** — For MAC, password, and signature verification.
4. **Never hardcode keys** — Use environment variables, KMS, or Vault.
5. **Use TLS 1.2+ with modern cipher suites** — Go 1.22+ has good defaults, but don't downgrade them.
6. **Use `golang.org/x/crypto`** — For bcrypt (passwords), argon2 (key derivation), ssh, and more.
7. **Use `crypto/tls` defaults** — Go's defaults are secure; only override to restrict, never to loosen.
8. **Run `gosec`** — Detects weak crypto algorithms, math/rand usage, InsecureSkipVerify.
9. **Test with `SSL Labs` tool** — Verify your TLS configuration externally.
10. **Rotate keys and review crypto code** — Annually by a security engineer.
