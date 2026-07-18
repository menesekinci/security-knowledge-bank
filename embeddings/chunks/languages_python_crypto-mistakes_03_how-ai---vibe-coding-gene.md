---
source: "languages/python/crypto-mistakes.md"
title: "Crypto Mistakes — Python"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 3/8
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