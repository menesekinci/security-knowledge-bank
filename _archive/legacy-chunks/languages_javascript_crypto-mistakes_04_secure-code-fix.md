---
source: "languages/javascript/crypto-mistakes.md"
title: "Crypto Mistakes — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 4
total_chunks: 7
heading: "Secure Code Fix"
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