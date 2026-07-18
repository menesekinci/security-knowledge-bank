# Side-Channel Risks in Python

> **Category:** Side-Channel Attacks  
> **Language:** Python  
> **Severity:** Medium to High  
> **CVEs covered:** CVE-2023-50782 (python-cryptography Bleichenbacher padding/timing oracle), CVE-2024-23342 (python-ecdsa Minerva), CVE-2021-23336 (Python urllib parameter cloaking)

## Overview

Side-channel attacks in Python exploit unintended information leakage through error messages, timing, exception content, memory usage, and even network packet sizes. Unlike traditional vulnerabilities, side-channels don't break the cryptographic primitives — they exploit the environment around them.

### Common Python Side-Channel Classes

1. **Padding Oracle Attacks** — Error messages reveal whether decryption padding is valid
2. **Exception-Based Oracles** — Different exception types leak information about internal state
3. **Cache Timing Side-Channels** — Cache hit/miss differences reveal memory access patterns
4. **Error Message Enumeration** — Verbose errors leak user existence, file paths, or configuration
5. **Size Side-Channels** — Response sizes differing by input value

---

## CVE-2023-50782: python-cryptography — Bleichenbacher Padding/Timing Oracle

**CVSS:** 7.5 (High)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-50782

### Description

The `cryptography` package before 42.0.0 exposed a Bleichenbacher timing oracle in RSA decryption with PKCS#1 v1.5 padding (the "Marvin" attack family; an incomplete fix for CVE-2020-25659). The time taken to process a ciphertext differed depending on whether the recovered PKCS#1 v1.5 padding was well-formed, which is a classic side channel: the primitive is not broken, but the *padding-validity signal* leaks through response timing. An attacker who can submit chosen ciphertexts and measure timing (for example against a TLS server using RSA key exchange) can act as a padding oracle and decrypt captured messages without the private key.

### The Oracle

The leak is the difference between "padding valid" and "padding invalid" being observable — whether through distinct error handling, distinct exceptions, or measurable timing:

```python
# VULNERABLE (cryptography < 42.0.0): PKCS#1 v1.5 RSA decryption whose
# processing time reveals whether the padding was well-formed.
from cryptography.hazmat.primitives.asymmetric import padding

def unwrap(private_key, ciphertext):
    # Bleichenbacher/Marvin oracle: timing differs on valid vs invalid padding
    return private_key.decrypt(ciphertext, padding.PKCS1v15())  # 💥
```

### Exploit Flow

1. Attacker captures an RSA-encrypted ciphertext (e.g. a TLS pre-master secret)
2. Sends many mathematically-related ciphertexts to the server
3. Measures response timing to learn "padding valid" vs "invalid" for each
4. Runs Bleichenbacher's algorithm to iteratively recover the plaintext
5. Recovers the session key / secret without ever holding the private key

### Fixed Code

```python
# 1) Upgrade cryptography to >= 42.0.0 (constant-time PKCS#1 v1.5 handling).
# 2) Prefer OAEP over PKCS#1 v1.5 for new designs — it is not subject
#    to the Bleichenbacher/Marvin oracle class.
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def unwrap_secure(private_key, ciphertext):
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
- https://people.redhat.com/~hkario/marvin/ — The Marvin Attack
- https://robotattack.org/ — Return of Bleichenbacher's Oracle Threat

---

## CVE-2024-23342: python-ecdsa — Minerva Timing Side-Channel

**CVSS:** 7.4 (High)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-23342

### Description

The pure-Python `ecdsa` library (through 0.18.0) is vulnerable to the Minerva timing attack on the P-256 curve. Scalar multiplication during signing is not constant-time, so the time taken by `SigningKey.sign_digest()` correlates with the bit-length of the per-signature secret nonce. This is a timing side channel: by collecting many (signature, timing) pairs an attacker recovers the nonces via a lattice attack and from them the long-term private key. Signing, key generation, and ECDH are affected; verification is not. The project treats side channels as out of scope, so there is no patch — migrate away.

### Side-Channel Mechanism

```python
from ecdsa import SigningKey, NIST256p

sk = SigningKey.generate(curve=NIST256p)

# VULNERABLE: signing latency leaks the nonce bit-length (Minerva).
def sign(digest: bytes) -> bytes:
    return sk.sign_digest(digest)  # 💥 non-constant-time scalar multiply
```

### Mitigation

```python
# python-ecdsa will not fix this. Migrate signing to a constant-time
# backend such as `cryptography` (OpenSSL constant-time ECDSA).
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

## CVE-2021-23336: Python Web Cache Poisoning Side-Channel

**CVSS:** 5.3 (Medium)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-23336

### Description

Python's `urllib.parse.parse_qsl()` and `parse_qs()` (before 3.6.13 / 3.7.10 / 3.8.8 / 3.9.2) split query strings on **both** `&` and `;`, while most proxies and caches only treat `&` as a separator. This mismatch enabled parameter cloaking: attackers could craft URLs that intermediaries (CDNs, reverse proxies) and the Python application interpreted differently, causing web cache poisoning.

### Side-Channel Mechanism

The vulnerability was in how Python's URL parser handled semicolons (`;`) as query parameter separators — a behavior inherited from older RFCs. When a CDN or proxy treated `;` differently from Python, cache poisoning became possible.

```python
# Python's parser treats ';' as a separator in query parameters
# URL: /api?auth_token=valid;user=admin
# Python sees: auth_token=valid, user=admin
# CDN sees: auth_token=valid;user=admin (single parameter)
```

### Exploit

1. Attacker crafts URL with semicolons that Python interprets differently
2. Request hits CDN cache — CDN caches based on its own interpretation
3. Subsequent users receive cached response intended for attacker-controlled parameters

### Fix

```python
# Python 3.9.2+ / 3.8.8+ / 3.7.10+ / 3.6.13+
# The fix made '&' the only default query separator (';' no longer splits)
# Use only '&' as query parameter separator:
# /api?auth_token=valid&user=admin

# Upgrade Python to patched version
# Or use custom parsing:
from urllib.parse import urlsplit, parse_qs
import re

def parse_url_safe(url: str) -> dict:
    """Parse URL without semicolon ambiguity."""
    # Remove semicolons that could cause confusion
    cleaned = re.sub(r';(?=\w+=)', '&', url)
    parsed = urlsplit(cleaned)
    return parse_qs(parsed.query)
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2021-23336
- https://www.sentinelone.com/vulnerability-database/cve-2021-23336/

---

## Additional Python Side-Channel Patterns

### Pattern 1: Boolean-Based Enumeration

```python
# VULNERABLE: Boolean oracle in user enumeration
def login(username, password):
    user = User.query.filter_by(email=username).first()
    if not user:
        return False, "User not found"  # Different message = oracle
    if not check_password(user, password):
        return False, "Invalid password"  # Different message
    return True, "Login successful"

# SECURE: Generic error message
def login_secure(username, password):
    user = User.query.filter_by(email=username).first()
    if not user:
        # Always "check" to normalize timing
        check_password_dummy(password)
        return False, "Invalid credentials"
    if not check_password(user, password):
        return False, "Invalid credentials"
    return True, "Login successful"
```

### Pattern 2: Timing Side-Channel in List Operations

```python
# VULNERABLE: 'in' operator on list vs set
def check_permission_vulnerable(user_id, allowed_users: list):
    # O(n) for lists — timing grows with position of match
    return user_id in allowed_users

# SECURE: Use set for O(1) consistent timing
def check_permission_secure(user_id, allowed_users: set):
    return user_id in allowed_users
```

### Pattern 3: Exception Content Leakage

```python
# VULNERABLE: Stack traces in API responses
from flask import Flask, jsonify

@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        "error": str(error),  # Leaks file paths, SQL queries, etc.
        "traceback": traceback.format_exc()  # Full stack trace
    }), 500

# SECURE: Sanitized error responses
@app.errorhandler(Exception)
def handle_error_secure(error):
    # Log the full error internally
    app.logger.error(f"Internal error: {traceback.format_exc()}")
    # Return sanitized message
    return jsonify({
        "error": "An internal error occurred"
    }), 500
```

---

## Detection and Prevention

### Tools

- **Timing attack detection:** `timing_attack` package for Python
- **Error message auditing:** Custom Semgrep rules for `traceback.format_exc()` in endpoints
- **Static analysis:** Bandit rule `B106` for hardcoded passwords, custom rules for error verbosity

### Secure Coding Checklist

| Pattern | Vulnerable | Secure |
|---------|-----------|--------|
| Error responses | Different for each failure type | Uniform generic errors |
| Password check | `User not found` vs `Wrong password` | Always `Invalid credentials` |
| API enumeration | `404` vs `403` vs `200` | Same response for unauthorized |
| Stack traces | Exposed in production | Logged internally only |
| Exception types | Different types for different failures | Single sanitized exception |
| Timing | Short-circuit comparisons | Constant-time operations |

---

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2023-50782 — python-cryptography Bleichenbacher/Marvin padding-timing oracle
2. https://github.com/advisories/GHSA-3ww4-gg4f-jr7f — python-cryptography advisory (CVE-2023-50782)
3. https://nvd.nist.gov/vuln/detail/CVE-2024-23342 — python-ecdsa Minerva P-256 timing side-channel
4. https://nvd.nist.gov/vuln/detail/CVE-2021-23336 — Python urllib parameter cloaking / web cache poisoning
5. https://robotattack.org/ — The ROBOT attack (Bleichenbacher oracle)
6. https://people.redhat.com/~hkario/marvin/ — The Marvin Attack
7. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle — OWASP padding oracle testing
