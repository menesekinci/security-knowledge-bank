# Cryptographic Failures — Weak Ciphers, Hardcoded Keys, Bad RNG, Hashing Mistakes

**CWE Categories:** CWE-327 (Broken/Risky Crypto Algorithm), CWE-259 (Hardcoded Password), CWE-330 (Insufficiently Random Values), CWE-328 (Reversible One-Way Hash), CWE-916 (Insufficient Password Hash Effort)
**OWASP Top 10:2021:** A02 — Cryptographic Failures (up from #3 to #2 in 2021, 233k+ occurrences)
**CWE Top 25 2024:** Multiple crypto-related CWEs tracked across several categories

---

## What Are Cryptographic Failures?

Cryptographic failures occur when applications **fail to properly protect sensitive data** through encryption, hashing, or random number generation. This includes using weak algorithms, hardcoding keys, generating predictable random values, and improperly storing passwords.

**The impact:** Sensitive data exposure, credential theft, session hijacking, man-in-the-middle attacks, and complete loss of data confidentiality/integrity.

## Why Vibe Coding Makes This Worse

AI code generators are particularly bad at cryptography because:

- **AI optimizes for "it works" not "it's secure":** Weak ciphers like DES, RC4, and ECB mode "work" but are insecure
- **AI selects the fastest hash:** MD5 and SHA1 are fast and commonly found in training data
- **Hardcoded secrets are in training data:** AI has seen millions of code snippets with `SECRET_KEY = "changeme"`
- **AI doesn't know about forward secrecy, nonce reuse, or padding oracle attacks**
- **AI generates `random()` for security:** Uses `Math.random()` or `random.randint()` instead of cryptographically secure RNG

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

## Cryptographic Algorithm Comparison

| Algorithm | Strength | Use For | Do NOT Use For |
|---|---|---|---|
| AES-256-GCM | ✅ Strong | Data encryption at rest/in transit | Password hashing |
| ChaCha20-Poly1305 | ✅ Strong | Mobile/low-power encryption | Password hashing |
| RSA-4096 | ✅ Strong | Key exchange, digital signatures | Bulk encryption |
| ECDSA (P-256) | ✅ Strong | Digital signatures | Encryption |
| Argon2id | ✅ Strong | Password hashing | Reversible encryption |
| bcrypt | ✅ Strong | Password hashing | Reversible encryption |
| SHA-256/384/512 | ✅ Strong | Integrity verification | Password hashing (unsalted) |
| MD5 | ❌ Broken | Nothing | Everything |
| SHA1 | ❌ Broken (SHAttered) | Nothing secure | Digital signatures |
| DES/3DES | ❌ Broken | Nothing | Everything |
| RC4 | ❌ Broken | Nothing | Everything |
| AES-ECB | ❌ Broken | Nothing | Anything non-random |
| RSA-1024 | ❌ Weak | Nothing (≤1024 deprecated) | New implementations |

---

## Password Hashing Recommendations

| Algorithm | Work Factor | Memory | Parallelism | Notes |
|---|---|---|---|---|
| **Argon2id** | t=3, m=64MB | ✅ High | ✅ Yes | PHC winner, best option |
| **bcrypt** | cost=12 | 🟡 Low | ❌ No | Good, widely available |
| **scrypt** | N=2^16, r=8, p=1 | ✅ High | ❌ Limited | Good alternative |
| **PBKDF2** | 310,000 iterations | ❌ Low | ❌ No | Baseline, GPU-resistant |

---

## Prevention Checklist for AI Prompts

```
✅ CRYPTOGRAPHY REQUIREMENTS FOR THIS CODE:
- NEVER hardcode keys, secrets, or passwords — use environment variables or a secrets manager
- Use AES-256-GCM or ChaCha20-Poly1305 for encryption (NOT ECB, CBC without MAC, or stream ciphers)
- Use Argon2id for password hashing (fallback: bcrypt cost ≥ 12, then scrypt, then PBKDF2)
- NEVER use MD5 or SHA1 for security purposes
- Use cryptographically secure random (secrets module in Python, crypto.randomBytes in Node.js)
- Never use Math.random(), random.random(), or similar for security tokens
- Generate a unique IV/nonce for EVERY encryption operation
- Use authenticated encryption (GCM, ChaCha20-Poly1305) that provides integrity AND confidentiality
- Always verify TLS certificates — never set rejectUnauthorized=false
- Enforce HTTPS with HSTS headers
- Use minimum key sizes: AES-256, RSA-3072+, ECDSA P-256+
- Rotate keys regularly and have a key rotation procedure
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Predictable SHA1PRNG `SecureRandom` (Apache Harmony / Android < 4.4) | CVE-2013-7372 | PRNG predictability enabled theft of Bitcoin wallet keys in the wild |
| Heartbleed — OpenSSL missing bounds check on Heartbeat packets | CVE-2014-0160 | Buffer over-read leaks process memory, including TLS private keys |
| SWEET32 — 64-bit block ciphers (3DES / Blowfish) birthday bound | CVE-2016-2183 | Plaintext recovery from long-lived TLS/SSH/VPN sessions |
| RC4 single-byte keystream biases in TLS/SSL | CVE-2013-2566 | Plaintext recovery via statistical analysis of many ciphertexts |
| Bleichenbacher/Marvin RSA timing oracle in python-cryptography (< 42.0.0) | CVE-2023-50782 | Decryption of captured RSA-encrypted TLS traffic (PKCS#1 v1.5 padding oracle) |
| Log4Shell — Log4j2 JNDI lookup with no endpoint restriction | CVE-2021-44228 | Unauthenticated RCE via attacker-controlled log message |
| SHA-1 collision (SHAttered) — **no CVE assigned** | N/A (SHAttered, 2017) | Colliding files / basis for forged digital signatures |

---

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [NIST SP 800-175B — Cryptographic Standards](https://csrc.nist.gov/publications/detail/sp/800-175b/rev-1/final)
- [CWE-327: Broken/Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-259: Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [Latacora — Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html)
