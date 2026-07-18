---
source: "languages/javascript/crypto-mistakes.md"
title: "Crypto Mistakes — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 6
total_chunks: 7
heading: "Real-World CVEs"
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2023-45133** | Node.js `crypto.createHash` bug in Babel | Hashed data manipulation |
| **CVE-2022-25839** | Node.js `url-parse` using Math.random for tokens | Token prediction |
| **CVE-2021-32688** | NextAuth.js `Math.random()` for session tokens | Session forgery |
| **CVE-2021-21239** | Django REST framework (JS SDK) weak token entropy | Token prediction |

---