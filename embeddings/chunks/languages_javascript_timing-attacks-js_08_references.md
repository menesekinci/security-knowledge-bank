---
source: "languages/javascript/timing-attacks-js.md"
title: "Timing Attack Vectors in JavaScript/TypeScript"
heading: "References"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [considerations, cve-2023-46809, cve-2026-21713, general, javascript, language-vuln, node, overview, timing, typescript-specific]
chunk: 8/8
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