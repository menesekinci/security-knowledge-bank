# Timing Attack Vectors in Python

> **Category:** Side-Channel / Timing Attacks  
> **Language:** Python  
> **Severity:** Medium to High  
> **CVEs covered:** CVE-2023-50782 (python-cryptography Marvin/Bleichenbacher timing), CVE-2020-25659 (python-cryptography Bleichenbacher timing), CVE-2024-23342 (python-ecdsa Minerva timing)

## Overview

Timing attacks exploit measurable differences in execution time to leak sensitive information. In Python, the most common vector is non-constant-time string comparison — the `==` operator short-circuits on the first differing byte, allowing an attacker to brute-force secrets character by character by measuring response times.

Despite Python's `hmac.compare_digest()` being available since 3.3, many applications still use `==` for comparing tokens, API keys, HMAC signatures, and passwords. This document covers real CVEs where timing leaks were exploitable in Python ecosystems.

---

## CVE-2023-50782: python-cryptography — Marvin/Bleichenbacher RSA Timing Oracle

**CVSS:** 7.5 (High)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-50782

### Description

The `cryptography` package before 42.0.0 was vulnerable to a Bleichenbacher timing oracle attack against RSA decryption with PKCS#1 v1.5 padding (a member of the "Marvin" attack family, and an incomplete fix for CVE-2020-25659). RSA PKCS#1 v1.5 decryption took a measurably different amount of time depending on whether the recovered padding was well-formed. A remote attacker who can submit ciphertexts and observe server response timing can act as a padding oracle, decrypting captured messages (e.g. TLS RSA key-exchange secrets) or forging signatures — without the private key.

### Vulnerable Code Pattern

```python
from cryptography.hazmat.primitives.asymmetric import padding

# Vulnerable: PKCS#1 v1.5 RSA decryption whose timing / error handling
# reveals whether padding was valid — a Bleichenbacher oracle.
def decrypt_pkcs1v15(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.PKCS1v15(),   # 💥 leaks padding validity via timing on < 42.0.0
    )
```

### Mitigation

```python
# 1) Upgrade cryptography to >= 42.0.0 (constant-time PKCS#1 v1.5 handling).
# 2) Prefer OAEP over PKCS#1 v1.5 for new designs — it is not affected
#    by the Bleichenbacher/Marvin class of oracles.
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def decrypt_oaep(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-50782
- https://github.com/advisories/GHSA-3ww4-gg4f-jr7f
- https://people.redhat.com/~hkario/marvin/

---

## CVE-2020-25659: python-cryptography — Bleichenbacher RSA Decryption Timing

**CVSS:** 5.9 (Medium)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2020-25659

### Description

`cryptography` 3.2 (and earlier) was vulnerable to Bleichenbacher timing attacks in the RSA decryption API, via timed processing of valid PKCS#1 v1.5 ciphertext. Non-constant-time error handling — separate error paths and key-specific error messages during RSA PKCS#1 v1.5 decryption — created measurable timing differences an attacker could exploit as a decryption oracle. This was the first fix in the chain; CVE-2023-50782 later addressed a remaining gap.

### Vulnerable Code Pattern

```python
from cryptography.hazmat.primitives.asymmetric import padding

# Vulnerable on cryptography 3.2 and earlier: RSA PKCS#1 v1.5 decryption
# whose error/timing behavior differs on valid vs invalid padding.
def unwrap_key(private_key, wrapped_key):
    return private_key.decrypt(wrapped_key, padding.PKCS1v15())  # 💥 timing oracle
```

### Fixed Code

```python
# Upgrade to cryptography >= 3.2 (this CVE) and >= 42.0.0 (CVE-2023-50782)
# for the complete constant-time fix. The remediation lives in the library's
# C implementation — application code is unchanged; upgrade the dependency.
# For new code, use OAEP instead of PKCS#1 v1.5.
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2020-25659
- https://bugzilla.redhat.com/show_bug.cgi?id=1889988

---

## CVE-2024-23342: python-ecdsa — Minerva ECDSA Nonce Timing Attack

**CVSS:** 7.4 (High)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-23342

### Description

The pure-Python `ecdsa` library (through 0.18.0) is vulnerable to the Minerva timing attack on the P-256 curve. Scalar multiplication in `ecdsa.SigningKey.sign_digest()` is not performed in constant time, so signing time correlates with the bit-length of the secret nonce. By timing many signatures an attacker can recover the nonce and, from it, the long-term private key. ECDSA signing, key generation, and ECDH are affected; signature verification is not. The maintainers consider side-channel resistance out of scope, so there is no code fix — migration is the remediation.

### Vulnerable Code Pattern

```python
from ecdsa import SigningKey, NIST256p

sk = SigningKey.generate(curve=NIST256p)

# Vulnerable: non-constant-time scalar multiplication.
# Signing latency leaks the nonce bit-length (Minerva).
def sign(message_digest: bytes) -> bytes:
    return sk.sign_digest(message_digest)  # 💥 timing leaks the nonce
```

### Mitigation

```python
# python-ecdsa will not fix this (side channels are out of scope).
# Migrate signing to a constant-time implementation, e.g. `cryptography`,
# which uses OpenSSL's constant-time ECDSA under the hood.
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

private_key = ec.generate_private_key(ec.SECP256R1())

def sign_secure(message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-23342
- https://github.com/advisories/GHSA-wj6h-64fc-37mp
- https://minerva.crocs.fi.muni.cz/

---

## General Vulnerable Patterns in Python

### Pattern 1: String Comparison with `==`

```python
# VULNERABLE: Short-circuit string comparison
def verify_token(user_token, expected):
    return user_token == expected
    # Returns False on first differing character — TIMING LEAK

# SECURE: Constant-time comparison
import hmac
def verify_token_secure(user_token, expected):
    if len(user_token) != len(expected):
        return False  # Still leaks length — ensure equal lengths
    return hmac.compare_digest(user_token, expected)
```

### Pattern 2: Password Verification

```python
# VULNERABLE
import bcrypt

def check_password_vulnerable(stored_hash, provided_password):
    # bcrypt is constant-time internally, but early return on format check leaks info
    if not stored_hash or len(stored_hash) != 60:
        return False  # Timing leak: valid hashes are 60 chars
    return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())

# SECURE
def check_password_secure(stored_hash, provided_password):
    # Always process regardless of perceived validity
    try:
        return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())
    except ValueError:
        # Invalid hash format — still take similar time
        bcrypt.checkpw(b"dummy", b"$2b$12$" + b"x" * 53)  # Pad timing
        return False
```

### Pattern 3: JWT/HMAC Verification

```python
# VULNERABLE: Custom HMAC comparison
import hashlib
import hmac

def verify_hmac_vulnerable(secret, message, signature):
    expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return expected == signature  # Timing leak via ==

# SECURE: Use compare_digest
def verify_hmac_secure(secret, message, signature):
    expected = hmac.new(secret, message, hashlib.sha256).digest()
    return hmac.compare_digest(expected, bytes.fromhex(signature))
```

---

## Detection Tools & Prevention

### Static Analysis

- **Semgrep rule:** `python.lang.security.audit.non-constant-time-comparison`
- **Bandit:** Use `bandit -r .` with custom rules for `==` in security contexts

### Runtime Protection

```python
import hmac
import time
import random

def constant_time_compare(a: str, b: str) -> bool:
    """Drop-in replacement for vulnerable == comparisons."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    # Normalize length
    max_len = max(len(a), len(b))
    a = a.ljust(max_len, '\x00')
    b = b.ljust(max_len, '\x00')
    return hmac.compare_digest(a.encode(), b.encode())
```

### Best Practices

1. **Always use `hmac.compare_digest()`** for comparing secrets, tokens, and HMACs
2. **Upgrade `cryptography` package** regularly (the Bleichenbacher/Marvin timing fix was completed in 42.0.0 — CVE-2023-50782)
3. **Avoid custom crypto implementations** — Python's standard library has constant-time primitives
4. **Add timing jitter** as defense-in-depth for high-security endpoints
5. **Use `secrets.compare_digest()`** (Python 3.8+) as a drop-in for constant-time comparison

---

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2023-50782 — python-cryptography Bleichenbacher/Marvin RSA timing oracle
2. https://nvd.nist.gov/vuln/detail/CVE-2020-25659 — python-cryptography Bleichenbacher RSA decryption timing
3. https://nvd.nist.gov/vuln/detail/CVE-2024-23342 — python-ecdsa Minerva P-256 nonce timing attack
4. https://sqreen.github.io/DevelopersSecurityBestPractices/timing-attack/python — Timing attacks against Python string comparison
5. https://docs.python.org/3/library/hmac.html#hmac.compare_digest — Python docs for compare_digest
6. https://codahale.com/a-lesson-in-timing-attacks/ — Classic timing attack primer
7. https://paragonie.com/blog/2015/11/preventing-timing-attacks-on-string-comparison-with-double-hmac-strategy — Double HMAC strategy
