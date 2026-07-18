---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
heading: "Real CVEs"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, panic, vulnerability]
chunk: 8/10
---

## Real CVEs

- **CVE-2020-29652 (golang.org/x/crypto/ssh, CVSS 7.5)**: A **nil pointer dereference** in the Go SSH server library let a remote, unauthenticated attacker crash any SSH server built on it — a pure availability (DoS) impact. Fixed in the commit series after `v0.0.0-20201203163018-be400aefbc4c`.
- **CVE-2026-39835 (golang.org/x/crypto/ssh, CVSS 5.3)**: SSH servers that use `CertChecker` as the public-key callback without setting `IsUserAuthority` or `IsHostAuthority` could be made to **panic (nil pointer dereference)** by a client that presents a certificate. `CertChecker` now returns an error instead of dereferencing the nil callback. Fixed in x/crypto 0.52.0.

Both are the classic AI pattern from this file: a value assumed to be non-nil (a callback, a checker field) is dereferenced on an untrusted-input path, turning a missing nil guard into a remote crash.