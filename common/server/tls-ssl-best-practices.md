# TLS / SSL Best Practices for Web Servers

- **Severity:** Critical
- **CWE:** CWE-327 (Broken Crypto), CWE-295 (Improper Cert Validation), CWE-326 (Weak Key), CWE-310 (Cryptographic Issues)
- **AI Generation Risk:** High

---

## 1. Vulnerability Explanation

AI-generated TLS/SSL configurations for web servers consistently exhibit fundamental security flaws. When prompted to "add HTTPS" or "secure with SSL," many LLMs default to outdated, weak, or outright insecure configurations. The most critical issues arise from:

### 1.1 Weak Protocol Versions

AI configurations frequently enable obsolete protocols:
- **SSLv2/v3** — Completely broken; no modern server should ever enable these
- **TLSv1.0** — Deprecated by PCI DSS, RFC 8996, and all major browsers since 2020
- **TLSv1.1** — Deprecated alongside TLSv1.0; all major browsers removed support in 2020-2021

AI-generated Nginx configs commonly contain `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;` — explicitly enabling two deprecated protocols.

### 1.2 Weak Cipher Suites

Outdated or weak cipher suites frequently appear in AI output:
- **RC4** — Fully broken; biases allow plaintext recovery
- **3DES (TLS_RSA_WITH_3DES_EDE_CBC_SHA)** — 64-bit block cipher vulnerable to Sweet32 (CVE-2016-2183)
- **EXPORT-grade ciphers** — Intentionally weakened (e.g., 40-bit keys); easily bruteforced
- **NULL ciphers** — Provide encryption but no authentication (anonymous)
- **aNULL / eNULL** — Anonymous or unencrypted suites

### 1.3 Self-Signed Certificates in Production

AI often generates self-signed certificate setups for production use:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout key.pem -out cert.pem
```
This creates a certificate not trusted by any browser or client, triggering security warnings.

### 1.4 Certificate Validation Bypassed in Code

AI code generation for backend services frequently disables TLS verification:
```python
# AI-generated, PRODUCTION CODE — DO NOT USE
requests.get('https://example.com', verify=False)
```
```java
// AI-generated TrustManager that trusts ALL certificates
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
};
```

### 1.5 Incorrect or Missing Certificate Chain

AI-generated TLS setups often present an incomplete certificate chain:
- Only the leaf certificate is served, without intermediate CA certificates
- Browsers and clients fail to validate the chain, causing "unable to get local issuer certificate" errors
- Some clients silently fall back to unencrypted connections

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

## 3. Vulnerable Code Examples

### 3.1 Python: Disabled Certificate Verification

```python
# ❌ VULNERABLE: No certificate verification — MitM possible
import requests
response = requests.get('https://api.example.com/data', verify=False)

# ❌ VULNERABLE: Implicitly trusting any cert
import urllib.request
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
response = urllib.request.urlopen('https://api.example.com', context=ctx)
```

### 3.2 Nginx: Weak TLS Configuration

```nginx
# ❌ VULNERABLE: Weak protocols and ciphers
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/ssl/cert.pem;          # Self-signed in production
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;              # ❌ TLSv1 and TLSv1.1 enabled
    ssl_ciphers RC4:HIGH:!aNULL:!eNULL:!EXPORT:!LOW;  # ❌ RC4 is completely broken
    ssl_prefer_server_ciphers on;
    # Missing ssl_certificate_trusted (no chain)
    # No HSTS
}
```

### 3.3 Java: Trust-All TrustManager

```java
// ❌ VULNERABLE: Trusts any certificate including self-signed
import javax.net.ssl.*;

TrustManager[] trustAll = new TrustManager[]{
    new X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[]{};
        }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
};

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAll, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

// All hostnames accepted — ❌
HostnameVerifier allHosts = (hostname, session) -> true;
HttpsURLConnection.setDefaultHostnameVerifier(allHosts);
```

### 3.4 Node.js: Incomplete Certificate Handling

```javascript
// ❌ VULNERABLE: No certificate authority chain
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
  // Missing: ca: fs.readFileSync('ca-chain.pem')
};

https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('hello world\n');
}).listen(443);

// ❌ VULNERABLE: RejectUnauthorized disabled
const requestOptions = {
  hostname: 'api.example.com',
  port: 443,
  path: '/data',
  rejectUnauthorized: false  // ❌ Accepts self-signed certs
};
```

### 3.5 Go: InsecureSkipVerify

```go
// ❌ VULNERABLE: Disables certificate validation
package main

import (
    "crypto/tls"
    "net/http"
)

func main() {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,  // ❌ Accepts any certificate
        },
    }
    client := &http.Client{Transport: tr}
    resp, _ := client.Get("https://api.example.com/data")
}
```

---

## 4. Secure Implementation

### 4.1 TLS Protocol Configuration (Mozilla Recommendations)

Use **Mozilla's Intermediate profile** as a baseline for broad compatibility with strong security. Use the **Modern profile** for services that only support modern clients.

#### Nginx (Modern)

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    ssl_certificate     /etc/nginx/ssl/fullchain.pem;   # Full chain
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_trusted_certificate /etc/nginx/ssl/chain.pem;   # Intermediate CA chain

    # Protocols — TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;

    # Ciphers — Modern profile (Mozilla)
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # HSTS — 2 years with preload
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Other security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
}
```

#### Apache (Modern)

```apache
<VirtualHost *:443>
    Protocols h2 http/1.1

    SSLEngine on
    SSLProtocol all -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    SSLSessionTickets off

    SSLCertificateFile /etc/ssl/certs/fullchain.pem
    SSLCertificateKeyFile /etc/ssl/private/privkey.pem
    SSLCertificateChainFile /etc/ssl/certs/chain.pem

    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"

    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
</VirtualHost>
```

#### Caddy (Automatic — Best Defaults)

```caddy
# Caddy automatically handles TLS with best practices:
# - ACME (Let's Encrypt / ZeroSSL) for certificate procurement
# - TLS 1.2 and 1.3 only
# - Strong cipher suites (cannot be overridden to weak ones)
# - Automatic HTTP→HTTPS redirects
# - OCSP stapling
# - HSTS by default

example.com {
    # TLS is automatic by default — no directives needed
    reverse_proxy localhost:3000
}
```

### 4.2 Certificate Chain Validation

**Always serve the complete certificate chain**, including all intermediate CA certificates:

```
Certificate chain
 0 s:CN = www.example.com          ← Leaf (server) certificate
   i:C = US, O = Let's Encrypt, CN = R3
 1 s:C = US, O = Let's Encrypt, CN = R3  ← Intermediate CA certificate
   i:C = US, O = Internet Security Research Group, CN = ISRG Root X1
```

**Construct the full chain file:**
```bash
cat /etc/letsencrypt/live/example.com/fullchain.pem
# Contains: leaf cert + intermediates + root (if included)
```

**Verify the chain:**
```bash
openssl s_client -connect example.com:443 -showcerts -servername example.com
```

### 4.3 ACME / Let's Encrypt Automation

**Never manually renew certificates.** Use ACME automation:

```bash
# certbot (recommended for Nginx/Apache)
certbot --nginx -d example.com -d www.example.com
certbot renew --quiet --deploy-hook "systemctl reload nginx"

# Or with systemd timer
# /etc/systemd/system/certbot-renew.timer
[Timer]
OnCalendar=daily
RandomizedDelaySec=43200
Persistent=true

# /etc/systemd/system/certbot-renew.service
[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx"
```

**Caddy** handles ACME automatically out of the box — no configuration needed.

### 4.4 Key Strength Requirements

| Key Type | Minimum | Recommended |
|----------|---------|-------------|
| RSA | 2048 bits | 4096 bits |
| ECDSA (P-256) | 256 bits | 256 bits |
| ECDSA (P-384) | 384 bits | 384 bits |
| Ed25519 | 256 bits | 256 bits |
| DH Params | 2048 bits | 4096 bits |

**Prefer ECDSA over RSA** for better performance and equivalent security:
```bash
# ECDSA key (preferred)
openssl ecparam -genkey -name prime256v1 -out privkey.pem

# RSA key (fallback)
openssl genrsa -out privkey.pem 4096
```

### 4.5 OCSP Stapling

OCSP Stapling allows the server to present a time-stamped OCSP response alongside its certificate, improving privacy and performance:

```nginx
# Nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 1.0.0.1 valid=300s;
```

```apache
# Apache
SSLUseStapling on
SSLStaplingResponderTimeout 5
SSLStaplingReturnResponderErrors off
SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
```

**Verify OCSP stapling is working:**
```bash
openssl s_client -connect example.com:443 -status -servername example.com
# Look for: OCSP Response Status: successful
```

### 4.6 HSTS (HTTP Strict Transport Security)

HSTS tells browsers to always connect via HTTPS, preventing downgrade attacks:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

**Preload** the domain in browser HSTS preload lists at [hstspreload.org](https://hstspreload.org/).

**Preload requirements:**
- Valid certificate on the root domain
- Redirect HTTP → HTTPS on all subdomains
- `includeSubDomains` directive
- `max-age` of at least 31536000 (1 year), 63072000 (2 years) recommended
- `preload` directive
- Submit to hstspreload.org

### 4.7 Certificate Pinning vs. Public Key Pinning

**⚠️ HTTP Public Key Pinning (HPKP) is deprecated** due to catastrophic failure modes (site becomes unreachable if key rotation is mismanaged).

**Alternative approaches:**
- **Certificate Transparency (CT)** — Monitor for mis-issued certificates via CT logs
- **Expect-CT header** — Deprecated; use CT monitoring instead
- **Content-Security-Policy `expect-ct`** — Not widely adopted
- **Multi-perspective validation** — Let's Encrypt uses multiple network perspectives

**Current best practice:** Use **certificate transparency monitoring** (e.g., [crt.sh](https://crt.sh/)) to detect unexpected certificate issuance, rather than pinning.

### 4.8 Secure Key Storage

- Store private keys with **0600** permissions, owned by root
- Use **HSM** (Hardware Security Module) or **KMS** (Key Management Service) for production
- Never commit private keys to source control
- Use **encrypted key files** when possible:
  ```nginx
  ssl_password_file /etc/nginx/ssl/passwords.txt;
  ```

---

## 5. Real CVEs (Web-Verified via NVD)

The following CVEs have been verified against the National Vulnerability Database (NVD) at time of writing.

| CVE ID | CVSS | CWE | Description | Affected Software |
|--------|------|-----|-------------|-------------------|
| [CVE-2024-5535](https://nvd.nist.gov/vuln/detail/CVE-2024-5535) | 9.1 Critical | CWE-126 | OpenSSL `SSL_select_next_proto` buffer overread when called with an empty supported client protocols buffer. May cause crash or memory content leak to the peer. | OpenSSL (multiple versions) |
| [CVE-2024-47252](https://nvd.nist.gov/vuln/detail/CVE-2024-47252) | 7.5 High | CWE-116 | Apache HTTP Server `mod_ssl` insufficient escaping of user-supplied data allows untrusted SSL/TLS clients to insert escape characters into log files. Can be used to inject false log entries or exploit log parsers. | Apache HTTP Server 2.4.0–2.4.63 |
| [CVE-2023-2650](https://nvd.nist.gov/vuln/detail/CVE-2023-2650) | 6.5 Medium | CWE-770 | OpenSSL OBJ_obj2txt() DoS via specially crafted ASN.1 object identifiers. Processing large sub-identifiers has O(n²) time complexity, leading to notable delays affecting OCSP, PKCS7/SMIME, CMS, CMP/CRMF, TS, and X.509 certificate processing. | OpenSSL 3.0.0–3.0.8, 3.1.0–3.1.0, 1.1.1–1.1.1t, 1.0.2–1.0.2zg |
| [CVE-2026-48697](https://nvd.nist.gov/vuln/detail/CVE-2026-48697) | 7.4 High | CWE-295 | Missing TLS certificate verification in FastNetMon Community Edition. The `execute_web_request_secure()` function creates an SSL context without calling `set_verify_mode(verify_peer)`, allowing MitM attacks on outbound HTTPS connections. | FastNetMon Community ≤1.2.9 |

### Additional Historic TLS CVEs (Reference)

| CVE ID | Year | Description |
|--------|------|-------------|
| CVE-2016-2183 | 2016 | **Sweet32** — 3DES 64-bit block cipher collision attack |
| CVE-2014-3566 | 2014 | **POODLE** — SSLv3 padding oracle attack |
| CVE-2015-0204 | 2015 | **FREAK** — EXPORT-grade RSA downgrade attack |
| CVE-2015-4000 | 2015 | **Logjam** — DH parameter downgrade to 512-bit export |
| CVE-2016-0800 | 2016 | **DROWN** — Cross-protocol attack on SSLv2 |
| CVE-2019-1559 | 2019 | OpenSSL 1.0.2 — 1.1.1 padding oracle MitM |

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

## Sources

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Certbot Documentation](https://certbot.eff.org/docs/)
- [Nginx HTTPS Configuration](https://nginx.org/en/docs/http/configuring_https_servers.html)
- [Apache mod_ssl Documentation](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html)
- [Caddy TLS Documentation](https://caddyserver.com/docs/automatic-https)
- [SSL Labs SSL Server Test](https://www.ssllabs.com/ssltest/)
- [HSTS Preload List](https://hstspreload.org/)
- [RFC 8996 — Deprecating TLS 1.0 and TLS 1.1](https://datatracker.ietf.org/doc/html/rfc8996)
- [NIST NVD Database](https://nvd.nist.gov/)
- [OpenSSL Security Advisories](https://www.openssl.org/news/vulnerabilities.html)
- [CWE-327: Broken or Risky Crypto Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
