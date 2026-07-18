---
source: "languages/javascript/timing-attacks-js.md"
title: "Timing Attack Vectors in JavaScript/TypeScript"
category: "language-vuln"
language: "javascript"
chunk: 2
total_chunks: 9
heading: "Overview"
---

## Overview

Timing attacks in JavaScript are particularly insidious because JavaScript's event loop, JIT compilation, and garbage collection introduce significant noise — masking the signal from timing leaks. However, Node.js's `crypto.timingSafeEqual()` provides constant-time comparison, and modern runtimes are actively working on timing-attack resistance.

The most common JS timing attack vectors are:
1. **HMAC/JWT signature validation** — non-constant-time string comparison
2. **Password/API key comparison** — short-circuit `===` operator
3. **User enumeration** — timing differences in database lookups
4. **JSON parsing** — JSON.parse timing reveals object structure
5. **Array operations** — indexOf/includes on arrays of different sizes

---