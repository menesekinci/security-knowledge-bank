---
source: "languages/rust/crypto-mistakes.md"
title: "Crypto Mistakes — ring, rust-crypto Misuse, Constant-Time Comparison"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [common, constant-time, crypto, language-vuln, overview, programming, ring, rust]
---

# Crypto Mistakes — ring, rust-crypto Misuse, Constant-Time Comparison
> **Severity:** High


## Overview

Cryptographic operations are notoriously sensitive to misuse. Even in a memory-safe language like Rust, crypto vulnerabilities thrive — not from memory corruption, but from **API misuse, incorrect algorithm choice, and side-channel leakage**. AI-generated crypto code is especially dangerous because LLMs frequently:

- Use outdated or broken algorithms (MD5, SHA-1, DES)
- Forget constant-time comparison for HMAC/verification
- Misuse cryptographic nonces/IVs
- Implement custom crypto instead of using audited libraries
- Handle secret keys unsafely (memory not zeroed, keys logged)

## How Rust's Safety Can Be Deceptive

Rust's compile-time checks give a false sense of security about crypto code. A function that compiles and passes tests can still be cryptographically broken:

```rust
// This compiles, is "safe" in Rust terms, but is completely broken crypto:
fn verify_hash(password: &str, hash: &str) -> bool {
    let computed = sha1::Sha1::from(password.as_bytes()).digest().to_string();
    computed == hash // SHA-1 is broken! Also not constant-time!
}
```

## Common Crypto Mistakes in AI-Generated Rust Code

### 1. Broken Cryptographic Hash Usage

```rust
// AI-GENERATED — uses MD5 for password hashing
use md5;

fn hash_password(password: &str) -> String {
    format!("{:x}", md5::compute(password.as_bytes()))
}
```

**Problems**:
- MD5 is cryptographically broken (collision attacks since 2004)
- No salt — rainbow table attack
- No work factor — fast to brute force
- No memory hardness

**Secure Fix**:
```rust
use argon2::{self, Config};

fn hash_password(password: &str) -> Result<String, argon2::Error> {
    let salt = salt::generate_secure_salt(); // Use a secure RNG
    let config = Config::default(); // Argon2id with recommended parameters
    argon2::hash_encoded(password.as_bytes(), &salt, &config)
}

fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::Error> {
    argon2::verify_encoded(hash, password.as_bytes())
}
```

### 2. Non-Constant-Time Comparison

The most common AI-generated crypto vulnerability:

```rust
// AI-GENERATED — timing-vulnerable comparison
fn verify_mac(message: &[u8], key: &[u8], expected_mac: &[u8]) -> bool {
    let computed_mac = compute_hmac_sha256(message, key);
    computed_mac == expected_mac // NOT constant-time!
}
```

**The Attack**: On modern CPUs, `==` on byte slices short-circuits on the first mismatching byte. An attacker can measure response time to determine *which byte* is wrong, then brute-force each byte one at a time. With 32-byte HMAC-SHA256, this reduces the attack from 2^256 to 256×256 = 65,536 operations.

**Secure Fix**:
```rust
use ring::constant_time::verify_slices_are_equal;

fn verify_mac(message: &[u8], key: &[u8], expected_mac: &[u8]) -> bool {
    let computed_mac = compute_hmac_sha256(message, key);
    verify_slices_are_equal(&computed_mac, expected_mac).is_ok()
    // Takes the SAME time regardless of how many bytes match
}
```

### 3. Incorrect Nonce/IV Generation

```rust
use aes::Aes256Gcm;
use aes_gcm::{AeadInOut, KeyInit, Nonce};

// AI-GENERATED — uses fixed nonce!
const NONCE: &[u8; 12] = b"123456789012";

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    // BUG: Same nonce every time = deterministic encryption + nonce reuse breaks AES-GCM completely
    cipher.encrypt(Nonce::from_slice(NONCE), plaintext).unwrap()
}
```

**The Attack**: AES-GCM nonce reuse allows an attacker to recover the authentication key and forge arbitrary ciphertexts. Reusing a nonce even once completely breaks security.

**Secure Fix**:
```rust
use ring::aead;

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)?;
    let nonce = aead::Nonce::assume_unique_for_key(aead::Nonce::generate(&mut ring::rand::SystemRandom::new()));
    let mut in_out = plaintext.to_vec();
    let sealing_key = aead::SealingKey::new(unbound_key);
    sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)?;
    Ok(in_out)
}
```

### 4. Using `rust-crypto` (Outdated)

Many AI models generate code using `rust-crypto` — a crate that was last updated in 2016 and is widely considered unmaintained:

```rust
// AI-GENERATED — uses unmaintained, potentially vulnerable rust-crypto
extern crate crypto;
use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize};
use crypto::blockmodes::PkcsPadding;

// This crate has no active maintainer, no security audits
```

**Secure Alternatives**: Use `ring` (BoringSSL-based, audited), `aws-lc-rs` (AWS crypto, FIPS), or `aes-gcm` / `aes-gcm-siv` (RustCrypto, actively maintained).

## The `ring` Crate: Safe API but Still Misusable

`ring` is one of the most audited Rust crypto libraries. However, AI still misuses it:

```rust
// AI-GENERATED — uses ring but with predictable random
use ring::rand::SystemRandom;

// Actually secure — SystemRandom is kernel entropy
let rng = SystemRandom::new();

// But AI sometimes generates this insecure alternative:
use ring::rand::SecureRandom;
// Tries to use a seedable RNG for keys:
let seed = [0u8; 32]; // BUG: Static seed!
```

## Constant-Time Programming

Rust does NOT provide automatic constant-time execution. Even safe Rust code can leak timing:

| Operation | Constant-Time? | Secure Alternative |
|---|---|---|
| `a == b` on byte slices | No | `ring::constant_time::verify_slices_are_equal` |
| `a != b` | No | `verify_slices_are_equal` and negate |
| String comparison | No | `subtle::ConstantTimeEq` trait |
| Boolean-based branching | No | `subtle::Choice` type |
| Array indexing with secret | No | Constant-time lookup tables |

## AI-Generated Vulnerability: Custom Encryption Algorithm

```rust
// AI-GENERATED — DO NOT USE: custom AES-like cipher
fn my_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    for (i, byte) in result.iter_mut().enumerate() {
        *byte ^= key[i % key.len()]; // Just XOR! This is NOT encryption!
    }
    result
}
```

**Never implement your own cryptography**. Use audited, battle-tested implementations.

## Real CVEs

- **RUSTSEC-2023-0071 / CVE-2023-49092 (`rsa`)**: The "Marvin Attack." The `rsa` crate's modular exponentiation is not constant-time, so an attacker who can observe the timing of decryption/signing operations can gradually recover the RSA private key — over the network. This is exactly the constant-time failure this page warns about, but in a core primitive rather than a MAC comparison. No fully fixed release at time of disclosure; the workaround is to avoid using `rsa` where an attacker can measure timing.
- **RUSTSEC-2022-0093 / CVE-2022-50237 (`ed25519-dalek`)**: Double public-key signing-function oracle. Versions before 2.0 let the public key be supplied separately from the private key when signing. Getting two signatures for the same message under two different public keys (sharing the same `R`) lets an attacker solve for the private key. Fixed in 2.0 by removing the unsafe decoupled-keypair signing API (it now lives behind a clearly labeled `hazmat` feature).
- **RUSTSEC-2016-0005 (`rust-crypto`)**: The `rust-crypto` crate (hyphenated — not the maintained RustCrypto org) has had no release or commit since 2016 and an unresponsive author. Depending on it means shipping cryptography that will never receive a security fix. Migrate to `ring`, `aws-lc-rs`, or the actively maintained RustCrypto crates (`aes-gcm`, `sha2`, etc.).

## Prevention Checklist

1. **Use `ring` or `aws-lc-rs`** — Both are audited, actively maintained, and designed to prevent misuse.
2. **Always use constant-time comparison** — Never use `==` for comparing MACs, signatures, or password hashes.
3. **Use Argon2id or bcrypt for passwords** — Never SHA-{1,256} directly (not memory-hard).
4. **Never implement custom crypto** — LLMs will invent algorithms. Reject them.
5. **Use `zeroize` crate** — Securely zero memory containing secrets after use.
6. **Use `secrecy` crate** — `Secret<T>` wrapper prevents accidental logging or debug-printing of secrets.
7. **Generate nonces/IVs with a CSPRNG** — Never hardcode or derive deterministically without a nonce-reuse mitigation.
8. **Pin dependency versions** — Crypto crate updates may subtly change behavior.
9. **Run `cargo audit`** — Detects vulnerable crypto crate versions.
10. **Review with a crypto expert** — Crypto bugs are invisible to both the compiler and standard tests.
