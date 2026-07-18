---
source: "languages/javascript/crypto-mistakes.md"
title: "Crypto Mistakes — JavaScript"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "javascript"
severity: "high"
tags: [checklist, code, cves, explanation, javascript, language-vuln, prevention, real-world, secure, vulnerability]
chunk: 3/7
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