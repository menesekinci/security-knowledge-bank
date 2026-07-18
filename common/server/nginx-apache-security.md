# Web Server Security: Nginx, Apache & Caddy

- **Severity:** High
- **CWE:** CWE-200 (Information Exposure), CWE-311 (Missing Encryption), CWE-524 (Cache Leak), CWE-16 (Configuration), CWE-352 (CSRF), CWE-400 (DoS), CWE-918 (SSRF)
- **AI Generation Risk:** High

---

## 1. Vulnerability Explanation

AI-generated web server configurations (Nginx, Apache, Caddy) frequently omit essential security hardening. Modern LLMs and "vibe coding" workflows produce functional configs that expose services unnecessarily, especially when the prompt lacks security-specific guidance.

### 1.1 Nginx Vulnerabilities

- **`server_tokens on`** — Exposes Nginx version strings in HTTP responses and error pages, giving attackers version-based targeting
- **`autoindex on`** — Directory listing enabled, leaking file/folder structure
- **No SSL/TLS** — HTTP-only configurations transmit data in plaintext
- **Weak ciphers/protocols** — AI defaults to TLSv1/TLSv1.1 with insecure ciphers like RC4, 3DES, or EXPORT-grade suites
- **No rate limiting** — Missing `limit_req` / `limit_conn` directives expose APIs to brute-force and DoS
- **No request body/buffer limits** — Default `client_max_body_size` (1MB) is small but missing `client_body_buffer_size` and `client_header_buffer_size` limits can lead to resource exhaustion
- **Unrestricted `proxy_pass`** — Passing user-controlled input to `proxy_pass` without validation enables SSRF
- **Missing security headers** — No `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, or `Referrer-Policy`
- **Default error pages** — Standard 404/403 pages expose server type and version

### 1.2 Apache Vulnerabilities

- **`Options +Indexes`** — Directory listing enabled, exposing file structure
- **`ServerSignature On`** / `ServerTokens Full` — Exposes Apache version and OS details
- **`mod_info` / `mod_status` exposed** — Sensitive server information accessible to any client
- **No HSTS** — Missing `Strict-Transport-Security` header allows protocol downgrade attacks
- **`AllowOverride All`** — Excessive `.htaccess` override permissions risk unintended config changes
- **Weak TLS defaults** — Apache 2.4 often ships with permissive default cipher lists
- **mod_rewrite unsafe patterns** — Vulnerable RewriteRules that enable SSRF or path traversal
- **No `LimitRequestBody`** — Unlimited POST body size enables DoS via large payloads
- **Default `ErrorDocument`** — Exposes server version and file paths

### 1.3 Caddy Vulnerabilities

- **`debug` mode enabled** — Exposes verbose request/response logging in production
- **Admin endpoint exposed** — Caddy's API admin endpoint (default `localhost:2019`) accessible without authentication
- **No `ask` endpoint** — Missing auth forwarding for forward auth scenarios
- **Insecure `tls` directives** — AI-generated configs may set `tls off` or `tls internal` without understanding the implications
- **Missing `trusted_proxies`** — Caddy may log incorrect client IPs, breaking rate limiting and audit
- **No `handle_path` sanitization** — Path traversal possible without proper sanitization

---

## 2. How AI / Vibe Coding Generates These Issues

Typical LLM prompts that produce insecure configurations:

| Prompt | What AI Returns | Security Gap |
|--------|----------------|--------------|
| "Generate Nginx config for my Node.js app" | Basic reverse proxy, no SSL, `server_tokens on`, no headers | No TLS, info leakage, no hardening |
| "Docker with Nginx + Alpine" | Minimal `nginx.conf`, default everything | No limits, no health checks, directory listing possibly on |
| "Apache virtual host for my PHP site" | `<VirtualHost>` with `Options +Indexes`, no HSTS | Directory listing, no TLS enforcement |
| "Caddyfile for static site" | `file_server browse` without auth | Full directory listing |
| "Add HTTPS to my Nginx config" | Self-signed cert, TLSv1.0, weak cipher suite | Incomplete TLS setup |
| "Rate limit my API" | `limit_req_zone` with burst=100, no dry-run testing | Either too permissive or too restrictive |
| "Docker Compose with reverse proxy" | Open `proxy_pass`, no access control | SSRF via forwarded host headers |

**Vibe coding amplification:** When developers iterate quickly using "make it work" prompts, security configuration is deferred. Each regeneration preserves insecure defaults because the prompt doesn't explicitly override them.

---

## 3. Vulnerable Config Examples

### 3.1 Nginx: Insecure Config

```nginx
server {
    listen 80;
    server_name example.com;

    server_tokens on;                         # INFO: exposes nginx version
    autoindex on;                             # BAD: directory listing

    ssl_protocols TLSv1 TLSv1.1;              # BAD: obsolete protocols
    ssl_ciphers RC4:HIGH:!aNULL:!eNULL;       # BAD: includes RC4

    location / {
        proxy_pass http://backend:3000;       # BAD: no input validation → SSRF risk
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
    }

    location /uploads/ {
        alias /var/www/uploads/;              # BAD: missing trailing slash → path traversal
    }

    # Missing security headers
    # Missing rate limiting
    # Missing client body limits
}
```

### 3.2 Apache: Insecure Config

```apache
<VirtualHost *:80>
    ServerName example.com
    ServerSignature On                        # BAD: exposes server version
    ServerTokens Full                         # BAD: full version details

    Options +Indexes +FollowSymLinks          # BAD: directory listing
    AllowOverride All                         # BAD: excessive override permissions

    <IfModule mod_info.c>
        <Location /server-info>
            SetHandler server-info
            # BAD: no access control
        </Location>
    </IfModule>

    <IfModule mod_status.c>
        <Location /server-status>
            SetHandler server-status
            # BAD: no access control
        </Location>
    </IfModule>

    # Missing TLS configuration
    # Missing HSTS
    # Missing security headers
</VirtualHost>
```

### 3.3 Caddy: Insecure Config

```caddy
{
    debug                                     # BAD: verbose logging in production
    admin 0.0.0.0:2019                        # BAD: admin API exposed
}

example.com {
    root * /var/www/site
    file_server browse                        # BAD: directory listing
    tls internal                              # BAD: self-signed in production

    reverse_proxy /api/* localhost:3000 {
        # Missing trusted_proxies
        # Missing header sanitization
    }
}
```

---

## 4. Secure Config Fix

### 4.1 Nginx: Secure Production Config

```nginx
# At http block level
server_tokens off;
more_set_headers "Server: ";                 # Or use server_tokens off + header override

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Buffer limits
client_body_buffer_size 128k;
client_header_buffer_size 1k;
client_max_body_size 10m;
large_client_header_buffers 4 8k;

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "0" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://backend:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection '';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Prevent SSRF: restrict proxy_pass targets
        # Use a whitelist approach — do NOT use variable-based proxy_pass with user input
        proxy_pass http://backend:3000;       # Static target, not user-controlled

        proxy_buffering off;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;

        limit_req zone=api burst=20 delay=10;
        limit_conn conn_limit 10;
    }

    location /uploads/ {
        alias /var/www/uploads/;
        autoindex off;
        # Validate file types
    }

    location = /robots.txt {
        add_header Content-Type text/plain;
        return 200 "User-agent: *\nDisallow:\n";
    }
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

### 4.2 Apache: Secure Production Config

```apache
<VirtualHost *:443>
    ServerName example.com
    ServerSignature Off
    ServerTokens Prod                         # Minimal server info

    # Security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "0"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    # Directory protection
    <Directory /var/www/html>
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    <Directory /var/www/html/uploads>
        Options -Indexes
        <FilesMatch "\.(php|pl|cgi|asp)$">
            Require all denied
        </FilesMatch>
    </Directory>

    # TLS — modern config
    Protocols h2 http/1.1
    SSLEngine on
    SSLProtocol all -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    SSLSessionCacheTimeout 86400

    # Rate limiting via mod_evasive (if enabled)
    <IfModule mod_evasive20.c>
        DOSHashTableSize 3097
        DOSPageCount 2
        DOSSiteCount 50
        DOSPageInterval 1
        DOSSiteInterval 1
        DOSBlockingPeriod 10
    </IfModule>

    # mod_info / mod_status restricted
    <IfModule mod_info.c>
        <Location /server-info>
            SetHandler server-info
            Require ip 127.0.0.1 ::1
        </Location>
    </IfModule>
    <IfModule mod_status.c>
        <Location /server-status>
            SetHandler server-status
            Require ip 127.0.0.1 ::1
        </Location>
    </IfModule>

    # Request body limit
    LimitRequestBody 10485760                # 10MB

    # Custom error pages (no version info)
    ErrorDocument 404 /errors/404.html
    ErrorDocument 403 /errors/403.html
    ErrorDocument 500 /errors/500.html
</VirtualHost>
```

### 4.3 Caddy: Secure Production Config

```caddy
{
    # admin off  # Uncomment to disable admin API entirely in production
    servers {
        trusted_proxies static 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
    }
}

example.com {
    root * /var/www/site
    file_server {
        hide .env .git .ht* *.log             # Hide sensitive files
    }

    # TLS with Let's Encrypt
    tls {
        issuer acme {
            dir https://acme-v02.api.letsencrypt.org/directory
        }
    }

    # Security headers via a reusable snippet
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        Permissions-Policy "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        -Server                                    # Remove Server header
    }

    @api path /api/*
    handle @api {
        reverse_proxy localhost:3000 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    @static file {
        path *.html *.css *.js *.png *.jpg *.gif *.svg *.ico
        not path /api/*
    }
    handle @static {
        root * /var/www/site/static
        file_server
    }

    # Rate limiting with Caddy's built-in rate_limit
    rate_limit {
        zone api {
            key {remote_host}
            events 10
            window 1s
        }
    }

    # Access logs (structured)
    log {
        output file /var/log/caddy/access.log {
            roll_size 100mb
            roll_keep 5
        }
        format json
    }
}
```

---

## 5. Reverse Proxy Security

### 5.1 SSRF Prevention

Server-Side Request Forgery via `proxy_pass` is one of the most critical web server misconfigurations.

**Vulnerable pattern:**
```nginx
# NEVER proxy to user-controlled input
location /proxy/ {
    set $backend $arg_target;
    proxy_pass http://$backend;               # SSRF: attacker can set target to internal services
}
```

**Secure pattern:**
```nginx
# Only proxy to known, whitelisted targets
upstream allowed_backend {
    server 127.0.0.1:3000;
    server 127.0.0.1:3001;
}

location /api/ {
    proxy_pass http://allowed_backend;
    # Never accept upstream targets from user input
}
```

**Additional protections:**
- Use `proxy_bind` to restrict outbound IP
- Validate `Host` header against an allowlist
- Disable HTTP redirect following (`proxy_redirect off`)
- Set `proxy_max_temp_file_size 0` to prevent disk writes
- Use `internal` directive to restrict locations to internal redirects only

### 5.2 Upstream Timeouts and Retries

```nginx
# Prevent hanging connections
proxy_connect_timeout 5s;
proxy_read_timeout 30s;
proxy_send_timeout 10s;

# Limit retries to avoid cascading failures
proxy_next_upstream error timeout;
proxy_next_upstream_tries 2;
proxy_next_upstream_timeout 5s;
```

### 5.3 WebSocket Proxy Security

```nginx
location /ws/ {
    proxy_pass http://ws_backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    # WebSocket-specific limits
    proxy_read_timeout 3600s;
    proxy_send_timeout 60s;

    # Validate Origin header
    if ($http_origin !~* (https?://(www\.)?example\.com)) {
        return 403;
    }
}
```

### 5.4 Apache Reverse Proxy Security

```apache
<VirtualHost *:443>
    ProxyPreserveHost On
    ProxyPass /api/ http://backend:3000/ timeout=30 retry=0
    ProxyPassReverse /api/ http://backend:3000/

    # Restrict proxy to specific paths
    <Location /api/>
        Require all granted
        ProxyPass http://backend:3000/
    </Location>

    # Block proxy to internal networks
    <ProxyMatch ^https?://(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])|192\.168\.)>
        Require all denied
    </ProxyMatch>
</VirtualHost>
```

---

## 6. Real CVEs (Web-Verified via NVD)

The following CVEs have been verified against the National Vulnerability Database (NVD) at time of writing.

### Nginx CVEs

| CVE ID | CVSS | CWE | Description | Affected Versions |
|--------|------|-----|-------------|-------------------|
| [CVE-2024-24989](https://nvd.nist.gov/vuln/detail/CVE-2024-24989) | 7.5 High | CWE-476 | NULL Pointer Dereference in HTTP/3 QUIC module allows worker process termination via undisclosed requests. Not enabled by default, experimental. | Nginx OSS 1.25.3, Nginx Plus R31 |
| [CVE-2024-35200](https://nvd.nist.gov/vuln/detail/CVE-2024-35200) | 5.3 Medium | CWE-476 | HTTP/3 QUIC module crash via undisclosed HTTP/3 requests causing worker termination. | Nginx OSS 1.25.0–1.26.0, Nginx Plus R30–R31 P1 |
| [CVE-2024-7347](https://nvd.nist.gov/vuln/detail/CVE-2024-7347) | 4.7 Medium | CWE-125/CWE-126 | Out-of-bounds read in `ngx_http_mp4_module` via crafted MP4 file, causing worker memory over-read and termination. Requires `mp4` directive. | Nginx OSS 1.5.13–1.26.1, Nginx Plus R27–R32 |

### Apache HTTP Server CVEs

| CVE ID | CVSS | CWE | Description | Affected Versions |
|--------|------|-----|-------------|-------------------|
| [CVE-2024-38475](https://nvd.nist.gov/vuln/detail/CVE-2024-38475) | 9.1 Critical | CWE-116 | Improper escaping in `mod_rewrite` allows attackers to map URLs to filesystem locations, enabling code execution or source disclosure. **Active exploitation** (CISA KEV). | Apache 2.4.0–2.4.59 |
| [CVE-2024-40898](https://nvd.nist.gov/vuln/detail/CVE-2024-40898) | 7.5–9.1 | CWE-918 | SSRF in `mod_rewrite` on Windows allows NTLM hash leak to malicious servers via server/vhost context. | Apache 2.4.0–2.4.61 (Windows only) |
| [CVE-2024-39573](https://nvd.nist.gov/vuln/detail/CVE-2024-39573) | 7.5 High | CWE-20 | SSRF in `mod_rewrite` allowing unsafe RewriteRules to route requests through `mod_proxy` unexpectedly. | Apache 2.4.0–2.4.59 |
| [CVE-2024-38472](https://nvd.nist.gov/vuln/detail/CVE-2024-38472) | 7.5 High | CWE-918 | SSRF on Windows allowing NTLM hash leak via malicious requests or content. | Apache ≤2.4.59 (Windows) |
| [CVE-2024-47252](https://nvd.nist.gov/vuln/detail/CVE-2024-47252) | 7.5 High | CWE-116 | Insufficient escaping in `mod_ssl` allows untrusted SSL/TLS clients to inject escape characters into log files. | Apache 2.4.0–2.4.63 |

### Caddy CVEs

Caddy has a smaller CVE footprint due to its modern design and automatic HTTPS. Common issues relate to misconfiguration rather than software vulnerabilities.

| CVE ID | CVSS | CWE | Description |
|--------|------|-----|-------------|
| No recent server-core CVEs | — | — | Caddy's automatic TLS and secure defaults reduce attack surface. Most Caddy risks are configuration-based: debug mode, open admin endpoints, missing auth. |

---

## 7. Prevention Checklist

- [ ] **Disable server tokens/signatures** — `server_tokens off` (Nginx), `ServerSignature Off` + `ServerTokens Prod` (Apache), remove `Server` header (Caddy)
- [ ] **Disable directory listing** — `autoindex off` (Nginx), `Options -Indexes` (Apache), no `file_server browse` (Caddy)
- [ ] **Enforce TLS 1.2+ only** — Block TLS 1.0/1.1 and SSLv2/v3
- [ ] **Set strong cipher suites** — Use Mozilla's Intermediate or Modern profile
- [ ] **Enable security headers** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- [ ] **Implement rate limiting** — `limit_req`/`limit_conn` (Nginx), `mod_evasive` (Apache), `rate_limit` (Caddy)
- [ ] **Set request body/buffer limits** — `client_max_body_size`, `client_body_buffer_size`, `client_header_buffer_size` (Nginx); `LimitRequestBody` (Apache)
- [ ] **Restrict reverse proxy targets** — Never proxy to user-controlled URLs; use whitelists
- [ ] **Validate `Host` and `Origin` headers** — Prevent host header injection and CSWSH
- [ ] **Secure error pages** — Custom error documents without version information
- [ ] **Restrict admin interfaces** — `mod_info`/`mod_status` to localhost only; disable Caddy admin in production
- [ ] **Enable access and error logging** — Structured JSON logs, log rotation, avoid logging sensitive data (tokens, passwords)
- [ ] **Use minimal privilege** — Run workers as non-root user; restrict file permissions
- [ ] **Regular updates** — Subscribe to Nginx [security advisories](https://nginx.org/en/security_advisories.html), Apache [vulnerability announcements](https://httpd.apache.org/security_report.html), Caddy [GitHub releases](https://github.com/caddyserver/caddy/releases)

---

## 8. Vibe-Coding Red Flags

Watch for these patterns in AI-generated web server configs:

1. **No `server_tokens off`** — The most common omission; AI defaults to showing versions
2. **`autoindex on` or `+Indexes`** — Directory listing exposed, especially in "simple static file server" configs
3. **HTTP-only (port 80) without redirect** — "listen 80" with no TLS upgrade
4. **`ssl_protocols TLSv1 TLSv1.1`** — Old protocols explicitly enabled
5. **`ssl_ciphers` with RC4, DES, or EXPORT** — Weak cipher suites included
6. **`proxy_pass http://$variable`** — User-controlled proxy target = instant SSRF
7. **No security headers at all** — The config works but provides zero browser-side protection
8. **`location / { alias /path; }`** — Missing trailing slash on `alias` enables path traversal
9. **`debug` mode in Caddy** — Verbose logging exposes request internals
10. **`AllowOverride All`** — Every directory gets `.htaccess` override, risky for shared hosting
11. **`Listen 0.0.0.0:80`** — Binds to all interfaces without consideration
12. **No `limit_req` / `limit_conn`** — APIs exposed to unlimited requests
13. **`proxy_pass` without `proxy_set_header Host $host`** — Backend receives wrong Host header
14. **`return 301 http://...`** — Redirect to HTTP instead of HTTPS
15. **No `client_max_body_size`** — Default 1MB may be too small or too large depending on application
16. **`tls internal` in Caddy production** — Self-signed certificate in production environments
17. **`server_name _;` without proper access control** — Catch-all server blocks leak data
18. **Exposing health check endpoints** — `/health`, `/status`, `/ping` without restriction
19. **No `internal` directive for sensitive locations** — Nginx `internal` prevents direct external access
20. **`add_header` in `location` block without `always`** — Headers not sent for error responses

---

## Sources

- [Nginx Security Advisories](https://nginx.org/en/security_advisories.html)
- [Nginx Configuring HTTPS Servers](https://nginx.org/en/docs/http/configuring_https_servers.html)
- [Apache HTTP Server Security Tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
- [Apache 2.4 Vulnerabilities](https://httpd.apache.org/security/vulnerabilities_24.html)
- [Caddy Security Documentation](https://caddyserver.com/docs/security)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [OWASP Reverse Proxy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Reverse_Proxy_and_API_Gateway_Cheat_Sheet.html)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
