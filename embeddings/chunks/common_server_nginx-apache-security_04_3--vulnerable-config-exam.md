---
source: "common/server/nginx-apache-security.md"
title: "Web Server Security: Nginx, Apache & Caddy"
heading: "3. Vulnerable Config Examples"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, config, explanation, proxy, reverse, secure, vulnerability, vulnerable]
chunk: 4/10
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