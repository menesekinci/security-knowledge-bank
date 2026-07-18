---
source: "languages/javascript/timing-attacks-js.md"
title: "Timing Attack Vectors in JavaScript/TypeScript"
heading: "General Timing Attack Patterns in JS/TS"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [considerations, cve-2023-46809, cve-2026-21713, general, javascript, language-vuln, node, overview, timing, typescript-specific]
chunk: 5/8
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