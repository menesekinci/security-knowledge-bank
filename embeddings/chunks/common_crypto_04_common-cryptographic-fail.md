---
source: "common/crypto.md"
title: "Cryptographic Failures — Weak Ciphers, Hardcoded Keys, Bad RNG, Hashing Mistakes"
heading: "Common Cryptographic Failures"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [algorithm, common, common-vuln, cryptographic, hashing, password, vibe, what]
chunk: 4/9
---

## Common Cryptographic Failures

### 1. Weak Hashing Algorithms (MD5, SHA1)

**Vulnerable Code — Password Hashing**
```python
import hashlib

# 🔴 VULNERABLE: MD5 — 5.6 billion hashes/second on consumer GPU
password_hash = hashlib.md5(password.encode()).hexdigest()

# 🔴 VULNERABLE: SHA1 — 8 billion hashes/second
password_hash = hashlib.sha1(password.encode()).hexdigest()

# 🔴 VULNERABLE: SHA256 — Fast, no salt, no work factor
password_hash = hashlib.sha256(password.encode()).hexdigest()
```

**Vulnerable Code — Node.js**
```javascript
const crypto = require('crypto');

// 🔴 VULNERABLE: MD5 (trivially cracked)
const hash = crypto.createHash('md5').update(password).digest('hex');

// 🔴 VULNERABLE: SHA1 without salt
const hash = crypto.createHash('sha1').update(password).digest('hex');
```

**Fixed Code — Password Hashing (Python)**
```python
import bcrypt
# OR: from argon2 import PasswordHasher

# ✅ SECURE: bcrypt with cost factor 12
salt = bcrypt.gensalt(rounds=12)
password_hash = bcrypt.hashpw(password.encode(), salt)

# ✅ SECURE: Argon2id (winner of PHC competition)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
password_hash = ph.hash(password)

# Verification
try:
    ph.verify(password_hash, password)
except argon2.exceptions.VerifyMismatchError:
    print("Invalid password")
```

**Fixed Code — Node.js**
```javascript
const bcrypt = require('bcrypt');

// ✅ SECURE: bcrypt
const salt = await bcrypt.genSalt(12);
const hash = await bcrypt.hash(password, salt);

// Verification
const match = await bcrypt.compare(password, storedHash);
```

### 2. Hardcoded Cryptographic Keys

**Vulnerable Code**
```python
# 🔴 VULNERABLE: hardcoded key
ENCRYPTION_KEY = "MySuperSecretKey123"  # 16 chars — way too short
IV = "1234567890123456"                  # Fixed IV — renders CBC useless

from Crypto.Cipher import AES
cipher = AES.new(ENCRYPTION_KEY.encode(), AES.MODE_CBC, IV.encode())
```

```javascript
// 🔴 VULNERABLE
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'secret';  // Trivially guessable

// 🔴 VULNERABLE: key in source code
const API_KEY = 'AIzaSyD...';  // Committed to git
```

```java
// 🔴 VULNERABLE: hardcoded in code
private static final String DB_PASSWORD = "password123";
```

**Fixed Code**
```python
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ✅ SECURE: key from environment / secret manager
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY').encode()
assert len(ENCRYPTION_KEY) == 32  # AES-256 requires 32-byte key

# ✅ SECURE: random IV every time
iv = get_random_bytes(16)
cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM, nonce=iv)
ciphertext, tag = cipher.encrypt_and_digest(data)
```

```javascript
// ✅ SECURE: from environment
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 256 bits');
}
```

### 3. Weak Random Number Generation

**Vulnerable Code**
```python
import random

# 🔴 VULNERABLE: Mersenne Twister (predictable)
reset_token = str(random.randint(100000, 999999))
# An attacker can predict this by observing a few tokens!

# 🔴 VULNERABLE: time-based "randomness"
import time
token = hash(str(time.time()))  # Trivially guessable
```

```javascript
// 🔴 VULNERABLE: Math.random() is NOT cryptographically secure
const resetToken = Math.random().toString(36).slice(2);
// Predictable — Mersenne Twister, seedable from timing
```

**Fixed Code**
```python
import secrets

# ✅ SECURE: cryptographically secure random
reset_token = secrets.randbelow(1000000)  # 0 to 999999
token_urlsafe = secrets.token_urlsafe(32)  # 32 bytes → 43 char URL-safe string
token_hex = secrets.token_hex(16)          # 16 bytes → 32 char hex string
```

```javascript
const crypto = require('crypto');

// ✅ SECURE: cryptographically strong
const resetToken = crypto.randomInt(100000, 999999);
const apiKey = crypto.randomBytes(32).toString('hex');
const uuid = crypto.randomUUID();  // v4 UUID
```

### 4. Weak Cipher Choice / ECB Mode

**Vulnerable Code**
```python
from Crypto.Cipher import AES

# 🔴 VULNERABLE: ECB mode — same plaintext blocks = same ciphertext blocks
#                                                                  ██ ██
# Famous problem: the "AES ECB penguin" — image encrypted with ECB   ██ ██
# still reveals the original image's silhouette!                     ██ ██
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(plaintext)
```

```javascript
const crypto = require('crypto');

// 🔴 VULNERABLE: DES (56-bit key — brute-forced in < 1 day)
const cipher = crypto.createCipheriv('des-cbc', key, iv);

// 🔴 VULNERABLE: RC4 (broken — biases in ciphertext)
const cipher = crypto.createCipher('rc4', key);
```

**Fixed Code**
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ✅ SECURE: AES-256-GCM (authenticated encryption)
key = get_random_bytes(32)
nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
# tag provides integrity verification — detects tampering

# ✅ SECURE: ChaCha20-Poly1305 (modern, fast, constant-time)
from Crypto.Cipher import ChaCha20_Poly1305
cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

```javascript
const crypto = require('crypto');

// ✅ SECURE: AES-256-GCM
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
```

### 5. Improper TLS / Missing Certificate Validation

**Vulnerable Code**
```python
import requests

# 🔴 VULNERABLE: skipping certificate verification
response = requests.get('https://api.bank.com', verify=False)

# 🔴 VULNERABLE: using HTTP
response = requests.get('http://api.bank.com')  # Plain text!
```

```javascript
// 🔴 VULNERABLE: skipping cert validation
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const https = require('https');
const req = https.request({
    hostname: 'api.bank.com',
    rejectUnauthorized: false  // Accepts ANY certificate!
});
```

**Fixed Code**
```python
# ✅ SECURE: verify certificates (default is True)
response = requests.get('https://api.bank.com')

# ✅ SECURE: enforce TLS
import os
os.environ['REQUESTS_CA_BUNDLE'] = '/etc/ssl/certs/ca-certificates.crt'
```

```javascript
// ✅ SECURE: always verify
const https = require('https');
const req = https.request({
    hostname: 'api.bank.com',
    rejectUnauthorized: true  // Default — keep it true
});
```

---