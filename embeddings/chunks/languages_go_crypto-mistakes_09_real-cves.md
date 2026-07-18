---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
heading: "Real CVEs"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [go, hardcoded, language-vuln, mistake, overview, timing-side, using]
chunk: 9/10
---

## Real CVEs

- **CVE-2023-24532 (crypto/internal/nistec, CVSS 5.3)**: The P-256 curve's `ScalarMult` and `ScalarBaseMult` methods returned an **incorrect result** (not a timing leak) when called with certain unreduced scalars larger than the order of the curve. This is a CWE-682 "incorrect calculation" bug; it did **not** affect `crypto/ecdsa` or `crypto/ecdh`, only direct users of the internal nistec package. Fixed in Go 1.19.7 and 1.20.2.
- **CVE-2024-45337 (golang.org/x/crypto/ssh, CVSS 9.1 Critical)**: An **authorization bypass** caused by applications misusing `ServerConfig.PublicKeyCallback`. Because the SSH protocol lets a client offer several public keys before proving ownership of any, an app that makes authorization decisions from a key other than the one finally authenticated could authorize the wrong identity. The fix guarantees the last key passed to the callback is the authenticated one. Fixed in x/crypto 0.31.0.
- **CVE-2025-22869 (golang.org/x/crypto/ssh, CVSS 7.5)**: A **denial of service** in the SSH server: a client that delays or never completes the key exchange makes the server accumulate unsent data in memory, exhausting resources. Fixed in x/crypto 0.35.0.