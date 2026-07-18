---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
category: "language-vuln"
language: "go"
chunk: 9
total_chunks: 10
heading: "Real CVEs"
---

## Real CVEs

- **CVE-2023-24532 (crypto/elliptic)**: A constant-time violation in P-256 scalar multiplication on 32-bit platforms. The non-constant-time code path leaked bits of the private key through timing side channels. Affected all Go applications using ECDSA on 32-bit systems.
- **CVE-2023-24540 (crypto/tls)**: A timing side channel in TLS 1.3 session ticket processing could allow an attacker to distinguish valid from invalid session tickets, enabling session enumeration.
- **CVE-2024-34158 (golang.org/x/crypto/ssh)**: An SSH handshake vulnerability in the Go SSH implementation could enable prefix truncation attacks against SHA-1-based HMAC — demonstrating that Go crypto is not immune to protocol-level attacks.