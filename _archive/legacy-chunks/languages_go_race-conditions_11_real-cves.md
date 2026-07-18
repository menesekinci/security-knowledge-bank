---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
category: "language-vuln"
language: "go"
chunk: 11
total_chunks: 12
heading: "Real CVEs"
---

## Real CVEs

- **CVE-2024-34158 (golang.org/x/net)**: Data race in the HTTP/2 server's handling of concurrent writes could cause a nil pointer dereference or incorrect frame ordering, leading to connection corruption.
- **CVE-2023-39325 (golang.org/x/net/http2)**: A race condition in HTTP/2 connection establishment could bypass stream limits, enabling resource exhaustion.
- **CVE-2023-24540 (crypto/tls)**: A data race in TLS 1.3 session ticket processing could cause the server to send incorrect session tickets, leading to authentication bypass in rare edge cases.