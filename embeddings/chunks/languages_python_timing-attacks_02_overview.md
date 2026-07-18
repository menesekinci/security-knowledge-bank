---
source: "languages/python/timing-attacks.md"
title: "Timing Attack Vectors in Python"
heading: "Overview"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [cve-2020-25659, cve-2023-50782, cve-2024-23342, general, language-vuln, overview, python, python-cryptography, python-ecdsa, vulnerable]
chunk: 2/8
---

## Overview

Timing attacks exploit measurable differences in execution time to leak sensitive information. In Python, the most common vector is non-constant-time string comparison — the `==` operator short-circuits on the first differing byte, allowing an attacker to brute-force secrets character by character by measuring response times.

Despite Python's `hmac.compare_digest()` being available since 3.3, many applications still use `==` for comparing tokens, API keys, HMAC signatures, and passwords. This document covers real CVEs where timing leaks were exploitable in Python ecosystems.

---