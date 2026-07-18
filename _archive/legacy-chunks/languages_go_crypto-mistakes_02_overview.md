---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
category: "language-vuln"
language: "go"
chunk: 2
total_chunks: 10
heading: "Overview"
---

## Overview

Go's standard library provides excellent cryptographic primitives (`crypto/aes`, `crypto/rsa`, `crypto/tls`, `golang.org/x/crypto`). However, the APIs are low-level and easy to misuse. AI-generated Go crypto code consistently makes the same mistakes: using `math/rand` for secrets, ECB mode for encryption, hardcoded keys, and incorrect nonce handling.