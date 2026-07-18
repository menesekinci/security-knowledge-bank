---
source: "common/server/tls-ssl-best-practices.md"
title: "TLS / SSL Best Practices for Web Servers"
heading: "7. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, cves, explanation, implementation, real, secure, vulnerability, vulnerable]
chunk: 8/9
---

## 7. Vibe-Coding Red Flags

Watch for these patterns in AI-generated TLS/SSL configurations:

1. **`ssl_protocols TLSv1 TLSv1.1 TLSv1.2`** — TLSv1.0 and TLSv1.1 should never appear
2. **Self-signed certificate in a "production" or "deployment" config** — "openssl req -x509" belongs in dev only
3. **`verify=False` or `CERT_NONE` in Python requests** — Almost always copy-pasted from a test example
4. **`InsecureSkipVerify: true` in Go configs** — Common in AI-generated clients
5. **Trust-all `TrustManager` in Java** — Boilerplate from Stack Overflow that AI learned from
6. **`rejectUnauthorized: false` in Node.js** — Same pattern, different language
7. **Missing `ssl_certificate_trusted` or `SSLCertificateChainFile`** — Incomplete chain = browser warnings
8. **`ssl_ciphers 'HIGH:!aNULL:!MD5'`** — Lazy cipher string that may include weak algorithms
9. **`ssl_session_tickets on` with no session key rotation** — Enables session resumption attacks
10. **No HSTS header** — Especially suspicious if the config has HTTPS enabled
11. **`return 301 http://` instead of `https://`** — Redirects to HTTP defeating SSL's purpose
12. **No `ssl_prefer_server_ciphers off`** — With modern profiles, client preference is recommended
13. **`SSLv3` anywhere in protocols** — Completely broken protocol
14. **EC2/cloud init scripts with hardcoded certs** — Self-signed certs created in provisioning scripts
15. **"Disable SSL verification for now" comments** — Indicates developer knows it's wrong but leaves it
16. **Missing OCSP stapling entirely** — Works without it but loses privacy/performance benefits
17. **`ssl_ciphers DEFAULT` or no cipher directive at all** — Leaves default (potentially weak) cipher list
18. **Single certificate file that's both the cert and key in one PEM** — Common AI misunderstanding
19. **No HTTP→HTTPS redirect** — Accepting HTTP traffic without redirection
20. **`tls internal` in Caddy production configs** — Caddy should use public ACME, not self-signed

---