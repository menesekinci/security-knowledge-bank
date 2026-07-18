# Timing Attack Vectors in JavaScript/TypeScript

> **Category:** Side-Channel / Timing Attacks  
> **Language:** JavaScript / TypeScript  
> **Severity:** Medium to High  
> **CVEs covered:** CVE-2023-46809 (Node.js RSA PKCS#1 v1.5 "Marvin" decryption timing), CVE-2026-21713 (Node.js Web Crypto HMAC/KMAC non-constant-time verification)

## Overview

Timing attacks in JavaScript are particularly insidious because JavaScript's event loop, JIT compilation, and garbage collection introduce significant noise — masking the signal from timing leaks. However, Node.js's `crypto.timingSafeEqual()` provides constant-time comparison, and modern runtimes are actively working on timing-attack resistance.

The most common JS timing attack vectors are:
1. **HMAC/JWT signature validation** — non-constant-time string comparison
2. **Password/API key comparison** — short-circuit `===` operator
3. **User enumeration** — timing differences in database lookups
4. **JSON parsing** — JSON.parse timing reveals object structure
5. **Array operations** — indexOf/includes on arrays of different sizes

---

## CVE-2023-46809: Node.js RSA PKCS#1 v1.5 Decryption Timing (Marvin Attack)

**CVSS:** 5.9 (Medium)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-46809

### Description

Node.js's `crypto.privateDecrypt()` with RSA `PKCS1_PADDING` was vulnerable to the **Marvin Attack** — a timing variant of the Bleichenbacher padding-oracle attack. Decryption took measurably different amounts of time for valid vs. invalid PKCS#1 v1.5 padding, leaking a timing oracle. An attacker who can measure these differences (e.g. against an endpoint that decrypts RSA ciphertexts or JWE messages) can gradually **decrypt captured ciphertexts or forge signatures without the private key**. Affected Node.js 18.x, 20.x, and 21.x lines that bundled or linked an unpatched OpenSSL. Fixed by disabling `RSA_PKCS1_PADDING` for `crypto.privateDecrypt()` in the February 2024 security releases.

### Vulnerable Code

```javascript
// VULNERABLE: RSA decryption with PKCS#1 v1.5 padding = padding-oracle timing leak
const crypto = require('crypto');

function decryptRSA(ciphertext) {
  // The time to process valid vs. invalid PKCS#1 v1.5 padding differs.
  // An attacker submitting many crafted ciphertexts can recover plaintext
  // one step at a time by measuring response latency (Marvin / Bleichenbacher).
  return crypto.privateDecrypt(
    {
      key: process.env.RSA_PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_PADDING,  // 💥 legacy padding, timing-sensitive
    },
    ciphertext
  );
}
```

### Secure Code

```javascript
// SECURE: Use OAEP padding (designed to resist padding-oracle attacks) + patched Node.js
const crypto = require('crypto');

function decryptRSASecure(ciphertext) {
  return crypto.privateDecrypt(
    {
      key: process.env.RSA_PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,  // ✅ OAEP, not v1.5
      oaepHash: 'sha256',
    },
    ciphertext
  );
}

// Also: upgrade to a Node.js release that carries the Feb 2024 OpenSSL fix,
// which disables RSA_PKCS1_PADDING for privateDecrypt() entirely.
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2023-46809
- https://nodejs.org/en/blog/vulnerability/february-2024-security-releases
- https://people.redhat.com/~hkario/marvin/

---

## CVE-2026-21713: Node.js Web Crypto HMAC/KMAC Non-Constant-Time Verification

**CVSS:** Medium  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-21713

### Description

Node.js's Web Cryptography API (`crypto.subtle.verify`) implemented HMAC and KMAC verification with a non-constant-time `memcmp()` when comparing the computed MAC against the user-supplied signature. The comparison returned as soon as it hit a differing byte, so the response time was proportional to the number of leading matching bytes. Under high-resolution measurement, this is a classic timing oracle that lets an attacker recover a valid MAC **byte by byte**. Fixed (March 24, 2026 security releases) by switching to a timing-safe comparison (`CRYPTO_memcmp`) in the HMAC and KMAC `verify` paths.

### Vulnerable Pattern

```javascript
// VULNERABLE: pre-fix Web Crypto HMAC verify used a byte-by-byte memcmp internally.
// Application code that trusts subtle.verify()'s timing inherits the leak:
async function verifyMac(key, signature, data) {
  // On affected Node.js builds, the time this resolves in leaks how many
  // leading bytes of `signature` matched the real MAC.
  return crypto.subtle.verify('HMAC', key, signature, data);
}
```

### Secure Code

```javascript
// SECURE: on patched Node.js, subtle.verify() is constant-time. If you must
// compare MACs yourself, use a constant-time primitive — never === / memcmp.
const crypto = require('crypto');

function verifyMacSecure(computedMac, providedMac) {
  // Both must be equal-length Buffers (see the timingSafeEqual limitations below)
  if (computedMac.length !== providedMac.length) return false;
  return crypto.timingSafeEqual(computedMac, providedMac);
}
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2026-21713
- https://nodejs.org/en/blog/vulnerability/march-2026-security-releases
- https://github.com/nodejs/node/commit/0f9332a40a

---

## General Timing Attack Patterns in JS/TS

### Pattern 1: String Comparison with `===`

```javascript
// VULNERABLE: Short-circuit string comparison
function verifyAPIKey(userKey, expectedKey) {
  return userKey === expectedKey;
  // Returns false on first differing character — TIMING LEAK
}

// SECURE: Use crypto.timingSafeEqual
const crypto = require('crypto');

function verifyAPIKeySecure(userKey, expectedKey) {
  if (userKey.length !== expectedKey.length) {
    // Length check leaks — normalize first
    return false;
  }
  return crypto.timingSafeEqual(
    Buffer.from(userKey),
    Buffer.from(expectedKey)
  );
}
```

### Pattern 2: Password Verification Timing

```javascript
// VULNERABLE
async function loginVulnerable(email, password) {
  const user = await db.users.findByEmail(email);
  if (!user) {
    // ~5ms query + immediate return
    return { error: 'User not found' };
  }
  // ~50ms bcrypt compare
  if (!await bcrypt.compare(password, user.hash)) {
    return { error: 'Wrong password' };
  }
  return { token: generateToken(user) };
}

// SECURE: Always do the expensive operation
async function loginSecure(email, password) {
  const user = await db.users.findByEmail(email);
  
  // Always do bcrypt compare — even if user doesn't exist
  let passwordValid = false;
  if (user) {
    passwordValid = await bcrypt.compare(password, user.hash);
  } else {
    // Use dummy hash so timing is identical
    const dummyHash = '$2b$12$' + 'x'.repeat(53);
    await bcrypt.compare(crypto.randomUUID(), dummyHash);
  }
  
  if (!user || !passwordValid) {
    return { error: 'Invalid credentials' };
  }
  return { token: generateToken(user) };
}
```

### Pattern 3: Array/Set Lookup Timing

```javascript
// VULNERABLE: O(n) array search timing
function checkPermissionVulnerable(userId, allowedUsers) {
  // Time grows with position of userId in array
  return allowedUsers.includes(userId);
}

// SECURE: O(1) Set lookup
function checkPermissionSecure(userId, allowedUsers) {
  const userSet = new Set(allowedUsers);
  return userSet.has(userId);
}
```

### Pattern 4: JSON.parse Timing Oracle

```javascript
// VULNERABLE: JSON.parse timing reveals data structure
function processData(jsonString) {
  const start = performance.now();
  const data = JSON.parse(jsonString);
  const elapsed = performance.now() - start;
  
  // Logging timing leaks (though attack must be network-based)
  logger.debug(`Parsed JSON in ${elapsed}ms`);
  
  // Different parse times for different structures reveal info
  // {"role":"admin"} parses faster than {"role":"admin","secret":"xxx"}
}
```

---

## TypeScript-Specific Considerations

TypeScript's type system is **compile-time only** — once compiled to JavaScript, all type information is erased. This means:

```typescript
// TypeScript types provide NO timing attack protection
function verifySecret(userInput: string, secret: string): boolean {
  // This is still vulnerable despite type safety!
  return userInput === secret;  // TIMING LEAK
}
```

### Using TypeScript to Prevent Timing Attacks

```typescript
import { timingSafeEqual } from 'crypto';

// Create a type-safe wrapper
type SecretString = string & { readonly __brand: 'Secret' };

function createSecret(value: string): SecretString {
  return value as SecretString;
}

function constantTimeCompare(
  input: string,
  secret: SecretString
): boolean {
  const inputBuf = Buffer.from(input);
  const secretBuf = Buffer.from(secret);
  
  if (inputBuf.length !== secretBuf.length) {
    return false;  // Still leaks length but not content
  }
  
  return timingSafeEqual(inputBuf, secretBuf);
}
```

---

## Node.js crypto.timingSafeEqual Limitations

```javascript
const crypto = require('crypto');

// LIMITATION 1: Buffer length must match
// If they differ, timingSafeEqual throws — this is a timing oracle!
try {
  crypto.timingSafeEqual(
    Buffer.from('short'),
    Buffer.from('very long secret')
  );
} catch (err) {
  // Exception thrown — attacker knows lengths differ!
}

// WORKAROUND: Pad to consistent length
function safeCompare(input, secret) {
  const maxLen = Math.max(input.length, secret.length);
  const inputPadded = Buffer.alloc(maxLen, input, 'utf-8');
  const secretPadded = Buffer.alloc(maxLen, secret, 'utf-8');
  return crypto.timingSafeEqual(inputPadded, secretPadded);
}

// LIMITATION 2: Not available in all environments
// Browser crypto.subtle doesn't have timingSafeEqual
// For browsers, use Double HMAC strategy:
async function browserSafeCompare(input, secret) {
  const encoder = new TextEncoder();
  const key1 = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  
  const inputHmac = await crypto.subtle.sign(
    'HMAC', key1, encoder.encode(input)
  );
  const secretHmac = await crypto.subtle.sign(
    'HMAC', key1, encoder.encode(secret)
  );
  
  // Compare HMACs — the HMAC is what leaks, not the secret itself
  return crypto.subtle.timingSafeEqual(inputHmac, secretHmac);
}
```

---

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2023-46809 — Node.js RSA PKCS#1 v1.5 "Marvin" decryption timing
2. https://nodejs.org/en/blog/vulnerability/february-2024-security-releases — Node.js Feb 2024 releases (CVE-2023-46809)
3. https://nvd.nist.gov/vuln/detail/CVE-2026-21713 — Node.js Web Crypto HMAC/KMAC non-constant-time verification
4. https://people.redhat.com/~hkario/marvin/ — The Marvin Attack (RSA PKCS#1 v1.5 timing)
5. https://developers.cloudflare.com/workers/examples/protect-against-timing-attacks/ — Cloudflare Workers timing attack protection
6. https://security.stackexchange.com/questions/237116/using-timingsafeequal — timingSafeEqual discussion
7. https://github.com/nodejs/node/issues/17178 — timingSafeEqual limitations
8. https://www.yagiz.co/timing-attacks-on-node-js — Node.js timing attacks overview
9. https://johnkavanagh.co.uk/articles/what-is-a-timing-attack-examples-and-safer-comparisons/ — Timing attack primer
