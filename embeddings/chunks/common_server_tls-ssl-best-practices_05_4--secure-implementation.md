---
source: "common/server/tls-ssl-best-practices.md"
title: "TLS / SSL Best Practices for Web Servers"
heading: "4. Secure Implementation"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, cves, explanation, implementation, real, secure, vulnerability, vulnerable]
chunk: 5/9
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