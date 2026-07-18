---
source: "languages/javascript/timing-attacks-js.md"
title: "Timing Attack Vectors in JavaScript/TypeScript"
heading: "Overview"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [considerations, cve-2023-46809, cve-2026-21713, general, javascript, language-vuln, node, overview, timing, typescript-specific]
chunk: 2/8
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