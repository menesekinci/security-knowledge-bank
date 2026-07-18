---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
heading: "Prevention Checklist"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [advanced, code, cves, go, language-vuln, overview, real, ssrf, vulnerable]
chunk: 8/8
---

## Prevention Checklist

1. **Validate and whitelist URLs** — Never pass user input directly to `http.Get()`.
2. **Restrict URL schemes** — Force HTTPS only; block `file://`, `gopher://`, `dict://`, `ftp://`.
3. **Block private and loopback IPs** — Use a custom `DialContext` that rejects `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`.
4. **Set timeouts** — `http.Client{Timeout: 5 * time.Second}` prevents slow-loris style SSRF.
5. **Restrict redirects** — Use `CheckRedirect` with max redirects and IP validation.
6. **Use a URL parser** — `net/url.Parse()` to validate before making requests.
7. **Log unusual request targets** — Alert on requests to metadata IPs or internal ranges.
8. **Use a dedicated HTTP client** — With restricted transport, never the default `http.DefaultClient`.
9. **Consider using a proxy** — Route all external requests through a forward proxy that enforces restrictions.
10. **Run `gosec`** — Detects unvalidated URL usage and weak transport controls.