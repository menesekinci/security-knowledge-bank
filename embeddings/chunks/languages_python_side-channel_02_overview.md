---
source: "languages/python/side-channel.md"
title: "Side-Channel Risks in Python"
heading: "Overview"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [additional, cve-2021-23336, cve-2023-50782, cve-2024-23342, language-vuln, overview, python, python-cryptography, python-ecdsa]
chunk: 2/8
---

## Overview

Side-channel attacks in Python exploit unintended information leakage through error messages, timing, exception content, memory usage, and even network packet sizes. Unlike traditional vulnerabilities, side-channels don't break the cryptographic primitives — they exploit the environment around them.

### Common Python Side-Channel Classes

1. **Padding Oracle Attacks** — Error messages reveal whether decryption padding is valid
2. **Exception-Based Oracles** — Different exception types leak information about internal state
3. **Cache Timing Side-Channels** — Cache hit/miss differences reveal memory access patterns
4. **Error Message Enumeration** — Verbose errors leak user existence, file paths, or configuration
5. **Size Side-Channels** — Response sizes differing by input value

---