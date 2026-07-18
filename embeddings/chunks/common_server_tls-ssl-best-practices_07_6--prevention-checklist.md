---
source: "common/server/tls-ssl-best-practices.md"
title: "TLS / SSL Best Practices for Web Servers"
heading: "6. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, cves, explanation, implementation, real, secure, vulnerability, vulnerable]
chunk: 7/9
---

## 6. Prevention Checklist

- [ ] **Use TLS 1.2 and TLS 1.3 only** — Disable SSLv2, SSLv3, TLSv1.0, TLSv1.1
- [ ] **Configure strong cipher suites** — Use Mozilla Intermediate or Modern profile; exclude RC4, 3DES, EXPORT, NULL, aNULL
- [ ] **Use trusted certificates** — Never use self-signed certs in production; use Let's Encrypt, ZeroSSL, or a commercial CA
- [ ] **Serve full certificate chain** — Include intermediate CA certificates; use `ssl_trusted_certificate` / `SSLCertificateChainFile`
- [ ] **Enable OCSP Stapling** — Improves privacy and performance; verify with `openssl s_client -status`
- [ ] **Set HSTS with preload** — `max-age=63072000; includeSubDomains; preload`; submit to hstspreload.org
- [ ] **Automate renewal** — Use certbot or Caddy's built-in ACME; never manually manage certs in production
- [ ] **Use strong key types and sizes** — Prefer ECDSA P-256; minimum RSA 2048 (recommend 4096)
- [ ] **Disable session tickets** — `ssl_session_tickets off` to prevent session resumption misuse
- [ ] **Secure private keys** — 0600 permissions, encrypted, never in source control
- [ ] **Verify TLS with SSL Labs** — Test at [ssllabs.com/ssltest/](https://www.ssllabs.com/ssltest/)
- [ ] **Monitor certificate expiration** — Set up alerts 7-14 days before expiry
- [ ] **Never disable certificate verification in code** — `verify=False`, `InsecureSkipVerify`, trust-all `TrustManager` are never acceptable in production
- [ ] **Use proper certificate validation in client code** — `verify_mode = CERT_REQUIRED` (Python), `rejectUnauthorized: true` (Node.js), `InsecureSkipVerify: false` (Go)
- [ ] **Implement Certificate Transparency monitoring** — Watch for unauthorized certificate issuance at [crt.sh](https://crt.sh/)
- [ ] **Deploy on modern web servers** — Caddy provides the best TLS defaults automatically; Nginx requires explicit configuration; Apache requires explicit configuration

---