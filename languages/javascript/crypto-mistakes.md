# Crypto Mistakes — JavaScript

> **Severity:** High
> **CVSS:** 7.5 (High)
> **AI Generation Risk:** High — AI models frequently use Math.random() for security purposes

---

## Vulnerability Explanation

JavaScript has a well-designed Web Crypto API (`crypto.subtle`) for both browser and Node.js environments. However, AI models frequently ignore it in favor of simpler APIs like `Math.random()`, or misuse the Crypto APIs with incorrect parameters.

### The Three Critical Mistakes

1. **`Math.random()` for security tokens, IDs, and keys** — Predictable PRNG
2. **Web Crypto API misuse** — Wrong algorithm parameters, unverified signatures
3. **Rolling your own crypto** — String manipulation "encryption"

---

## How AI / Vibe Coding Generates This

### 1. Math.random() for Everything

```javascript
// 🚫 VULNERABLE — AI-generated token
function generateToken() {
  return Math.random().toString(36).substr(2);  // 💥 Predictable!
}

// 🚫 VULNERABLE — AI-generated session ID
function createSessionId() {
  return 'sess_' + Math.random().toString(36).substr(2, 15);  // 💥
}

// 🚫 VULNERABLE — AI-generated password reset link
function generateResetToken() {
  return md5(Math.random().toString());  // 💥 Double whammy: weak PRNG + MD5
}
```

**Why Math.random() is insecure:** V8's `Math.random()` uses xorshift128+, a non-cryptographic PRNG. Given ~66 consecutive outputs, attackers can reconstruct the internal state and predict all future values.

### 2. Web Crypto API Misuse

```javascript
// 🚫 VULNERABLE — AI-generated encryption (wrong algorithm)
async function encrypt(data, password) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),  // 💥 Password directly as key — wrong!
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );
  
  const iv = crypto.getRandomValues(new Uint8Array(16));
  return crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, encoder.encode(data));
}
```

### 3. "Custom Encryption" (Rolling Your Own)

```javascript
// 🚫 VULNERABLE — AI-generated "encryption"
function encrypt(text, password) {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(
      text.charCodeAt(i) ^ password.charCodeAt(i % password.length)  // 💥 XOR cipher
    );
  }
  return btoa(result);  // "Obfuscated" with base64
}
```

### 4. MD5/SHA1 for Passwords

```javascript
// 🚫 VULNERABLE — AI-generated password hashing
const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');  // 💥 MD5 for passwords!
}
```

### 5. Weak Key Generation

```javascript
// 🚫 VULNERABLE — AI-generated key
const key = crypto.randomBytes(4).toString('hex');  // 💥 Only 32 bits!

// 🚫 VULNERABLE — AI-generated IV
const iv = '00000000000000000000000000000000';  // 💥 Static IV!
```

### 6. Missing Authentication in Encryption

```javascript
// 🚫 VULNERABLE — AES-CBC without HMAC
async function encrypt(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    key,
    data
  );
  // 💥 CBC without HMAC — attacker can modify ciphertext!
  return { iv, ciphertext };
}
```

---

## Secure Code Fix

### Fix 1: Use crypto.getRandomValues() Instead of Math.random()

```javascript
// ✅ SAFE — Cryptographic randomness
function generateToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);  // ✅ CSPRNG
  return Array.from(array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// In Node.js:
const crypto = require('crypto');
function generateToken() {
  return crypto.randomBytes(32).toString('hex');  // ✅ 256 bits of entropy
}
```

### Fix 2: Proper Password Hashing

```javascript
// ✅ SAFE — Use bcrypt (Node.js)
const bcrypt = require('bcrypt');

async function hashPassword(password) {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);  // ✅ Auto-generates salt
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}
```

### Fix 3: Proper Web Crypto API Usage

```javascript
// ✅ SAFE — AES-GCM authenticated encryption
async function encrypt(data, password) {
  // Step 1: Derive a proper key from password using PBKDF2
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 600000,  // OWASP recommended minimum
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  
  // Step 2: Encrypt with GCM (authenticated encryption)
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(data)
  );
  
  // Return salt + iv + ciphertext (all needed for decryption)
  return {
    salt: Array.from(salt),
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(ciphertext))
  };
}
```

### Fix 4: Proper HMAC Signatures (Node.js)

```javascript
// ✅ SAFE — HMAC with constant-time comparison
const crypto = require('crypto');

function createSignature(data, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('hex');
}

function verifySignature(data, signature, secret) {
  const expected = createSignature(data, secret);
  // Use timingSafeEqual — NOT ===
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(signature)
  );
}
```

### Fix 5: Use SubtleCrypto for Key Generation

```javascript
// ✅ SAFE — Generate proper cryptographic keys
async function generateEncryptionKey() {
  return crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,  // AES-256
    },
    true,   // Extractable (for export)
    ['encrypt', 'decrypt']
  );
}
```

### Fix 6: Use Node.js crypto for Password Hashing (Limited Use)

```javascript
// ✅ SAFE — PBKDF2 via Node.js crypto (use bcrypt/argon2 when possible)
const crypto = require('crypto');

function hashPasswordPBKDF2(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(
    password,
    salt,
    600000,   // Iterations (OWASP 2023 minimum)
    32,       // Key length (256 bits)
    'sha256'
  );
  return salt.toString('hex') + ':' + hash.toString('hex');
}

function verifyPasswordPBKDF2(password, stored) {
  const [salt, hash] = stored.split(':');
  const verify = crypto.pbkdf2Sync(
    password,
    Buffer.from(salt, 'hex'),
    600000,
    32,
    'sha256'
  );
  return crypto.timingSafeEqual(verify, Buffer.from(hash, 'hex'));
}
```

---

## Prevention Checklist

- [ ] NEVER use `Math.random()` for security purposes (tokens, passwords, keys, session IDs)
- [ ] Use `crypto.getRandomValues()` (browser) or `crypto.randomBytes()` (Node.js)
- [ ] Use `bcrypt` or `argon2` for password hashing — never use plain `hashlib`
- [ ] Use AES-GCM or ChaCha20-Poly1305 for encryption (authenticated modes)
- [ ] Never use ECB mode (leaks patterns), never use CBC without HMAC (tampering)
- [ ] Always generate a new random IV/salt for each encryption operation
- [ ] Use PBKDF2/Argon2/scrypt for key derivation from passwords, never raw keys
- [ ] Use `crypto.timingSafeEqual()` for all HMAC/signature comparison
- [ ] Keep key sizes: AES-128/256, RSA-2048+, ECC P-256+
- [ ] Use SubtleCrypto API properly with correct algorithm names

---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2023-46233** | `crypto-js` < 4.2.0 — default PBKDF2 uses SHA-1 with a single iteration (~1000x weaker than spec) | Weak key derivation; brute-forceable hashes (CVSS 9.1; fixed 4.2.0) |
| **CVE-2023-46234** | `browserify-sign` 2.6.0–4.2.1 — upper-bound check flaw in `dsaVerify` lets any public key verify crafted signatures | Signature forgery (CVSS 7.5; fixed 4.2.2) |
| **CVE-2022-24771** | `node-forge` < 1.3.0 — RSA PKCS#1 v1.5 signature verification too lenient on the digest structure | Signature forgery with low public exponent (fixed 1.3.0) |
| **CVE-2018-1000620** | `cryptiles` <= 4.1.1 — `randomDigits()` biased / insufficient entropy (CWE-331) | Predictable "random" security tokens (fixed 4.1.2) |

---

## Vibe Coding Red Flags

In AI-generated JavaScript, flag these immediately:

```javascript
Math.random() used for tokens/keys    // 💥 Predictable PRNG
crypto.createHash('md5') for passwords  // 💥 Broken hash
crypto.createHash('sha1') for passwords // 💥 Deprecated hash
btoa(string) for "encryption"          // 💥 Base64 != encryption
xor cipher implementation              // 💥 Roll-your-own crypto
static iv = [...]                      // 💥 Reused initialization vector
ecb mode encryption                    // 💥 ECB is deterministic
```

> **Golden Rule:** If AI-generated JavaScript uses `Math.random()` for anything security-related, it's a vulnerability. If it implements custom XOR/base64/"encryption", it's a vulnerability.
