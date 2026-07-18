---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
heading: "Real CVEs"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, algorithm, confusion, java, language-vuln, overview, vulnerability]
chunk: 8/10
---

## Real CVEs

- **CVE-2022-21449 (Psychic Signatures in Java)**: CVSS 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`) — A flaw in the JDK's ECDSA signature verification (Oracle Java SE 15–18, e.g. 17.0.2/18) meant that a blank/all-zero ECDSA signature `(r=0, s=0)` was always accepted as valid, regardless of the signed content. Any JWT library relying on the JDK for ES256/ES384/ES512 verification (Nimbus, jose4j, java-jwt) accepted forged tokens until the JDK was patched.
- **CVE-2023-52428 (Nimbus JOSE+JWT)**: CVSS 7.5 (`...S:U/C:N/I:N/A:H`) — Denial of service in Connect2id Nimbus JOSE+JWT before 9.37.2: an attacker supplies a JWE with a very large PBES2 `p2c` (PBKDF2 iteration count) header, forcing the `PasswordBasedDecrypter` into excessive CPU consumption.
- **CVE-2023-51775 (jose4j)**: CVSS 6.5 (`...PR:L/UI:N/S:U/C:N/I:N/A:H`) — The same class of PBES2 abuse in jose4j before 0.9.4: a large `p2c` (PBES2 Count) value causes a CPU-consumption denial of service.