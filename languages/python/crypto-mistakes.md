# Crypto Mistakes — Python

> **Severity:** High–Critical
> **CVSS:** 7.5 (High) — Weak crypto can lead to data breaches
> **AI Generation Risk:** High — AI models frequently misuse cryptography APIs and choose insecure defaults

---

## Vulnerability Explanation

Python developers (and AI coding assistants) regularly make three fundamental cryptographic mistakes:

1. **Using `random` instead of `secrets`** for security-sensitive operations
2. **Using weak/rolling-your-own crypto** instead of established libraries
3. **Misusing `cryptography` library APIs** — wrong modes, wrong IV handling, wrong key sizes

### The Random vs Secrets Problem

```python
import random

# 🚫 VULNERABLE — AI uses random for security tokens
token = ''.join(random.choices('abcdef0123456789', k=32))  # 💥 Predictable!
reset_link = f"https://example.com/reset?token={token}"
```

Python's `random` module uses the Mersenne Twister PRNG — NOT cryptographically secure. Given enough outputs, attackers can reconstruct the internal state and predict future values.

```python
import secrets

# ✅ SAFE — secrets module is CSPRNG-backed
token = secrets.token_hex(16)  # 32 hex chars, cryptographically random
reset_link = f"https://example.com/reset?token={token}"
```

### The "Roll Your Own Crypto" Problem

AI models frequently generate custom encryption implementations when prompted with "encrypt this data":

```python
# 🚫 VULNERABLE — AI-generated custom "encryption"
def encrypt(text, key):
    result = ""
    for i, c in enumerate(text):
        result += chr(ord(c) ^ ord(key[i % len(key)]))  # 💥 XOR cipher
    return result

# This is trivially breakable. AI often generates XOR, Caesar, or substitution ciphers.
```

---

## How AI / Vibe Coding Generates This

### 1. hashlib Misuse — Weak Hash Algorithms

```python
# 🚫 VULNERABLE — AI using weak hashes
import hashlib

def hash_password(password):
    # AI uses MD5 or SHA1 because they're "fast" and well-known
    return hashlib.md5(password.encode()).hexdigest()  # 💥 Broken — use bcrypt/argon2
```

### 2. cryptography Library Mode Confusion

```python
# 🚫 VULNERABLE — AI using ECB mode (deterministic, insecure)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_aes_ecb(key, plaintext):
    # AI defaults to ECB mode — every block encrypts identically
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # 💥 ECB leaks patterns!
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
```

### 3. Hardcoded Keys and IVs

```python
# 🚫 VULNERABLE — AI-generated crypto with hardcoded values
from cryptography.fernet import Fernet

# AI hardcodes the encryption key in the source code
key = b'mysecretkeymysecretkeymysecrets'  # 💥 Hardcoded!
f = Fernet(base64.urlsafe_b64encode(key))

def encrypt_data(data):
    return f.encrypt(data.encode())
```

### 4. Incorrect IV Handling

```python
# 🚫 VULNERABLE — AI reusing IV
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

key = os.urandom(32)
iv = b'\x00' * 16  # 💥 Static IV — defeats CBC security!

def encrypt(plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
```

### 5. Password Hashing Without Salt

```python
# 🚫 VULNERABLE — AI-generated password hashing
import hashlib

def store_password(password):
    # AI hashes without salt — rainbow table vulnerable
    hashed = hashlib.sha256(password.encode()).hexdigest()  # 💥 No salt!
    db.execute("INSERT INTO users (password) VALUES (?)", (hashed,))
```

### 6. Timing-Vulnerable Comparisons

```python
# 🚫 VULNERABLE — AI using == for HMAC/signature comparison
def verify_signature(data, signature):
    expected = hmac_sign(data)
    return expected == signature  # 💥 Timing attack! Attacker can byte-guess
```

### Why AI Does This

- **`random` is more common in training data** than `secrets` (80:1 ratio in seen code)
- **Hashing is the "first solution":** AI reaches for `hashlib.md5` or `hashlib.sha1` because they're taught first
- **No security engineering knowledge:** AI doesn't know about ECB pattern leakage, IV requirements, or timing attacks
- **API complexity:** The `cryptography` library's `hazmat` (hazardous materials) API is confusing — AI picks the simplest mode

---

## Vulnerable Code Example

### Token Generation with random

```python
# 🚫 VULNERABLE — Complete reset password flow
import random
import string
from flask import Flask, request

app = Flask(__name__)

@app.route('/reset-password')
def reset_password():
    user_id = request.args.get('uid')
    
    # AI generates reset token with random (PREDICTABLE!)
    chars = string.ascii_letters + string.digits
    token = ''.join(random.choices(chars, k=32))  # 💥 Mersenne Twister!
    
    store_token(user_id, token)
    send_email(f"Click here to reset: https://example.com/reset?token={token}")
    return "Check your email"

# Attackers who obtain one token can predict future tokens
# by recovering the PRNG state from observed tokens!
```

### Custom Encryption Implementation

```python
# 🚫 VULNERABLE — AI-generated secure messaging
def encrypt_message(message, password):
    """'Secure' encryption — actually just XOR."""
    # AI thinks this is secure encryption
    key = hashlib.md5(password.encode()).digest()  # 💥 MD5
    result = bytearray()
    for i, b in enumerate(message.encode()):
        result.append(b ^ key[i % len(key)])  # 💥 XOR
    return bytes(result)

# Both MD5 and XOR are trivial to break.
```

### Fernet with Wrong Key Encoding

```python
# 🚫 VULNERABLE — AI-generated Fernet misuse
from cryptography.fernet import Fernet
import base64

# AI tries to use a raw string as a Fernet key
f = Fernet("my-secret-key")  # 💥 TypeError or wrong encoding
# Correct: Fernet expects 32 url-safe base64-encoded bytes
```

---

## Secure Code Fix

### Fix 1: Use secrets for Security-Sensitive Randomness

```python
# ✅ SAFE — Use secrets module
import secrets

def generate_token():
    return secrets.token_urlsafe(32)  # 256 bits of entropy

def generate_reset_link(user_id):
    token = secrets.token_urlsafe(32)
    store_token(user_id, token)
    return f"https://example.com/reset?token={token}"
```

### Fix 2: Proper Password Hashing

```python
# ✅ SAFE — Use bcrypt or argon2
import bcrypt

def hash_password(password):
    # bcrypt auto-generates salt, includes cost factor
    salt = bcrypt.gensalt(rounds=12)  # 2^12 iterations
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)
```

### Fix 3: Use Fernet (High-Level Crypto)

```python
# ✅ SAFE — Use Fernet for symmetric encryption
from cryptography.fernet import Fernet

# Generate a proper key once, store in env vars
key = Fernet.generate_key()  # 128-bit key, properly formatted
f = Fernet(key)

def encrypt_data(data: bytes) -> bytes:
    return f.encrypt(data)  # Authenticated encryption!

def decrypt_data(token: bytes) -> bytes:
    return f.decrypt(token)  # Verifies authenticity
```

### Fix 4: Proper AES-GCM (Authenticated Encryption)

```python
# ✅ SAFE — AES-GCM with proper IV handling
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_aes_gcm(key: bytes, data: bytes) -> bytes:
    # GCM provides confidentiality + authentication
    aad = b"authenticated but not encrypted data"
    
    # Generate a new IV for EVERY encryption
    iv = os.urandom(12)  # 96-bit recommended for GCM
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data, aad)
    
    # IV must be stored alongside ciphertext
    return iv + ciphertext

def decrypt_aes_gcm(key: bytes, encrypted: bytes) -> bytes:
    # Extract IV from first 12 bytes
    iv = encrypted[:12]
    ciphertext = encrypted[12:]
    
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)
```

### Fix 5: Timing-Safe Comparison

```python
# ✅ SAFE — Use hmac.compare_digest for constant-time comparison
import hmac

def verify_signature(data, signature):
    expected = hmac_sign(data)
    return hmac.compare_digest(expected, signature)  # ✅ Constant-time!
```

### Fix 6: Use hashlib with Proper Algorithms

```python
# ✅ SAFE — Use SHA-256 or SHA-3 for integrity
import hashlib

def hash_file(filepath):
    h = hashlib.sha256()  # Not MD5, not SHA-1
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

# For password hashing specifically:
# NEVER use hashlib for passwords — use bcrypt, argon2, or scrypt
```

---

## Prevention Checklist

- [ ] NEVER use `random` module for security tokens, passwords, keys — use `secrets`
- [ ] NEVER use MD5 or SHA-1 for security purposes (integrity only, not passwords)
- [ ] Use `bcrypt`, `argon2`, or `scrypt` for password hashing (not plain SHA)
- [ ] Use `Fernet` for simple symmetric encryption (handles IV, auth, padding)
- [ ] Use AES-GCM or ChaCha20-Poly1305 for custom encryption (authenticated modes)
- [ ] NEVER hardcode keys/IVs — use environment variables or a KMS
- [ ] ALWAYS generate a new random IV for each encryption call
- [ ] Use `hmac.compare_digest()` for signature/token comparison
- [ ] Use `secrets.token_hex()`, `secrets.token_urlsafe()`, `secrets.randbelow()`
- [ ] Use `hashlib.pbkdf2_hmac()` if you must derive keys from passwords
- [ ] Keep key sizes at industry standards: AES-128/256, RSA-2048+, ECC P-256+

---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2013-1445** | PyCrypto ≤2.6 — `Crypto.Random` PRNG not reseeded after `os.fork()`, so a child reuses the parent's random state | Predictable keys/tokens across processes |
| **CVE-2018-6594** | PyCrypto/pycryptodome — weak ElGamal key generation (generator is not a quadratic residue, breaking the DDH assumption) | Ciphertext recoverable; no semantic security |
| **CVE-2022-29217** | PyJWT <2.4.0 — algorithm/key confusion: a public key can be accepted as an HMAC secret when `algorithms` is unspecified | JWT forgery / auth bypass |
| **CVE-2020-36242** | python-cryptography <3.3.2 — integer overflow → buffer overflow when symmetrically encrypting multi-GB values (e.g. via `Fernet`) | Memory corruption / crash |
| **CVE-2020-13757** | python-rsa <4.1 — PKCS#1 v1.5 decryption/verification ignores prepended `\0` bytes (padding length not validated) | Ciphertext/signature malleability, info disclosure |

---

## Vibe Coding Red Flags

In AI-generated Python, flag these immediately:

```python
random.choice(...) for tokens          # 💥 Not cryptographic
random.shuffle(...) for security       # 💥 Predictable
random.getrandbits(...)                # 💥 Mersenne Twister
hashlib.md5(...) for passwords         # 💥 Broken hash
hashlib.sha1(...) for passwords        # 💥 Deprecated hash
bytes(key, 'utf-8') for crypto        # 💥 Wrong key encoding
ecb = modes.ECB()                      # 💥 ECB mode leaks patterns
iv = b'\x00' * 16                      # 💥 Static IV
cipher = ... + ...  (custom)           # 💥 Roll-your-own crypto
```

> **Golden Rule:** Any use of `random` for security purposes is automatically a vulnerability. Any use of MD5/SHA1 for passwords is a vulnerability. Any custom encryption implementation is a vulnerability.
