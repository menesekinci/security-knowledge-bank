---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
category: "language-vuln"
language: "go"
chunk: 8
total_chunks: 10
heading: "Real CVEs"
---

## Real CVEs

- **CVE-2023-39326 (net/netip)**: A nil pointer dereference in the `netip` package could be triggered by parsing malformed IP address strings from untrusted input, causing denial of service in any application parsing IP headers.
- **CVE-2023-44487 (golang.org/x/net/http2)**: While primarily an HTTP/2 protocol issue, the Go http2 implementation had multiple nil pointer dereference paths triggered by RST_STREAM frames during connection teardown.
- **CVE-2022-41717 (net/http)**: A nil pointer dereference in HTTP/2's `Server.Push` handler caused server crashes when receiving specially crafted push requests.