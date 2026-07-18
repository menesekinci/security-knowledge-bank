---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
category: "language-vuln"
language: "go"
chunk: 6
total_chunks: 8
heading: "Real CVEs"
---

## Real CVEs

- **CVE-2024-34156 (golang.org/x/net/http/httpproxy)**: SSRF vulnerability in Go's HTTP proxy handling. When using proxy environment variables (HTTP_PROXY, HTTPS_PROXY), a crafted proxy URL could bypass host matching patterns and redirect requests to arbitrary internal destinations — including cloud metadata endpoints.
- **CVE-2023-45142 (golang.org/x/net/html)**: Not SSRF directly, but the HTML tokenizer's vulnerability could be exploited via SSRF to download and process malicious HTML from attacker-controlled servers.
- **CVE-2023-39325 (golang.org/x/net/http2)**: The HTTP/2 rapid reset vulnerability in Go could be exploited via SSRF — an attacker who controlled where a Go app made requests could force it to consume server resources via rapid stream resets.