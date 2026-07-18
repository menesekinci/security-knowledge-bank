---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
category: "language-vuln"
language: "java"
chunk: 8
total_chunks: 10
heading: "Real CVEs"
---

## Real CVEs

- **CVE-2024-29972 (Nimbus JOSE+JWT)**: CVSS 7.5 — Improper handling of HMAC keys shorter than the minimum required length could lead to signature bypass in Nimbus JOSE+JWT before version 9.40.
- **CVE-2023-44487 (Nimbus JOSE+JWT)**: CVSS 5.3 — A denial of service via excessively large JWT payload parsing in Nimbus JOSE+JWT could lead to resource exhaustion.
- **CVE-2022-21449 (Psychic Signatures in Java)**: CVSS 7.5 — A vulnerability in Java's ECDSA signature verification (CVE-2022-21449, "Psychic Signatures") meant that certain ECDSA signatures were always accepted as valid, regardless of the actual signature value. This affected all Java ECDSA-based JWT verification until the JDK patch.