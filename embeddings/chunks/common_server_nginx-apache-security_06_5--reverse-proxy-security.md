---
source: "common/server/nginx-apache-security.md"
title: "Web Server Security: Nginx, Apache & Caddy"
heading: "5. Reverse Proxy Security"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, config, explanation, proxy, reverse, secure, vulnerability, vulnerable]
chunk: 6/10
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