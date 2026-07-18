---
source: "languages/python/crypto-mistakes.md"
title: "Crypto Mistakes — Python"
heading: "Secure Code Fix"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 5/8
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