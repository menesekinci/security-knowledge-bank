---
source: "common/server/nginx-apache-security.md"
title: "Web Server Security: Nginx, Apache & Caddy"
heading: "4. Secure Config Fix"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, config, explanation, proxy, reverse, secure, vulnerability, vulnerable]
chunk: 5/10
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