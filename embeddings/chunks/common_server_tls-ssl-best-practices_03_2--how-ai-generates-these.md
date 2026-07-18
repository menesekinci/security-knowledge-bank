---
source: "common/server/tls-ssl-best-practices.md"
title: "TLS / SSL Best Practices for Web Servers"
heading: "2. How AI Generates These Issues"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, cves, explanation, implementation, real, secure, vulnerability, vulnerable]
chunk: 3/9
---

## 2. How AI Generates These Issues

| Prompt | AI Output | Security Gap |
|--------|-----------|-------------|
| "Add HTTPS to my Nginx config" | Self-signed cert, TLS 1.0 + 1.1 + 1.2, weak ciphers | Obsolete protocols, untrusted cert |
| "Python requests to API" | `requests.get(url, verify=False)` or missing `verify` | No certificate validation |
| "Java SSL socket example" | Trust-all `TrustManager` | MitM possible |
| "Docker Nginx with SSL" | Default `ssl_protocols`, no cipher override | Weak protocol defaults |
| "Generate Let's Encrypt cert" | Often references `certbot` but misses auto-renewal setup | Expired certs |
| "Node.js HTTPS server" | `https.createServer({key, cert})` without `ca` chain | Incomplete chain |
| "Ruby Net::HTTP with TLS" | Opens connection without `verify_mode = OpenSSL::SSL::VERIFY_PEER` | No verification |
| "Go HTTP server with TLS" | `tls.Config{InsecureSkipVerify: true}` | MitM in production |
| "Create self-signed cert for local dev" | Script with no SAN (Subject Alternative Name) | Browser trust errors |
| "NGINX config with TLS 1.3" | Sometimes enables TLS 1.3 but keeps weak ciphers | Mix of strong/weak |

### Root Cause in AI Behavior

LLMs prioritize functional output over security-hardened output unless explicitly prompted otherwise. When generating configuration:
1. They use the **shortest path** to a "working" configuration
2. They **default to well-known examples** from blogs and documentation that may be outdated
3. They **avoid complexity** — adding complete certificate chains, ACME automation, or OCSP stapling increases output length
4. They **rarely include warnings or alternatives** unless specifically asked

---