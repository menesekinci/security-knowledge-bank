# HTTP Request Smuggling

**CWE:** CWE-444 (Inconsistent Interpretation of HTTP Requests)
**OWASP Top 10:2021:** A04 — Insecure Design

---

## What Is HTTP Request Smuggling?

HTTP Request Smuggling exploits **differences in how front-end servers (proxies, load balancers, CDNs) and back-end servers parse HTTP requests**. Attackers craft ambiguous requests that the front-end interprets as one request but the back-end interprets as multiple requests. This "smuggles" a malicious second request past security controls.

**The impact:** Session hijacking, authentication bypass, cross-user request poisoning, cache poisoning, firewall bypass.

## How It Works

HTTP/1.1 supports two ways to specify request body length:
- **Content-Length (CL):** `Content-Length: 13` — exactly 13 bytes
- **Transfer-Encoding (TE):** `Transfer-Encoding: chunked` — body is split into chunks

When front-end and back-end disagree on which header to trust, smuggling occurs.

## Common Smuggling Techniques

### CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```
- **Front-end** reads `Content-Length: 13` → body is `0\r\n\r\nGET /admin...`
- **Back-end** reads `Transfer-Encoding: chunked` → `0` means body ends → treats `GET /admin` as NEW request!

### TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /admin HTTP/1.1
Content-Length: 15

x=1
0
```

### TE.TE (Obfuscating Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
```

## Why Vibe Coding Makes This Worse

- **AI rarely configures HTTP parsers:** Generated code uses default server settings that may be inconsistent
- **AI sets up reverse proxies:** AI generates nginx/Apache configs but may mismatch parser behavior
- **AI-generated applications behind CDN:** Without understanding HTTP parsing differences
- **HTTP/1.1 keepalive:** Smuggling requires persistent connections — AI enables keepalive by default

## Vulnerable Configurations

### Nginx → Node.js

```nginx
# 🔴 VULNERABLE: nginx defaults may conflict with Node.js parsing
server {
    listen 80;
    location / {
        proxy_pass http://node_backend;
        proxy_http_version 1.1;
    }
}
```

### Apache → Tomcat

```apache
# 🔴 VULNERABLE: Apache and Tomcat parse Transfer-Encoding differently
<VirtualHost *:80>
    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/
</VirtualHost>
```

## Fixed Configurations

### Nginx — Disable HTTP/1.1 keepalive to backends

```nginx
# ✅ SECURE: mitigate smuggling
server {
    listen 80;
    location / {
        proxy_pass http://node_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}

# Or better: use HTTP/2
server {
    listen 443 ssl http2;
    # HTTP/2 is largely immune to request smuggling
}
```

### Use Consistent Parser Settings

```nginx
# ✅ SECURE: explicitly drop requests with conflicting headers
server {
    if ($http_transfer_encoding ~* "chunked") {
        set $te "chunked";
    }
    if ($content_length) {
        set $cl "content_length";
    }
}
```

### Application-Level Defense (Node.js)

```javascript
// ✅ SECURE: reject ambiguous requests
app.use((req, res, next) => {
    if (req.headers['content-length'] && req.headers['transfer-encoding']) {
        return res.status(400).send('Bad Request');
    }
    const te = req.headers['transfer-encoding'];
    if (te && te.toLowerCase() !== 'chunked') {
        return res.status(400).send('Bad Request');
    }
    next();
});
```

### Use HTTP/2 or HTTP/3

```nginx
# ✅ BEST: use HTTP/2 — immune to smuggling
server {
    listen 443 ssl http2;
    http2 on;
    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;
    }
}
```

## Impact Examples

| Attack Vector | What Attacker Can Do |
|---|---|
| Request smuggling | Bypass WAF/firewall rules |
| Cross-user poisoning | Poison cached pages — all users served attacker content |
| Session hijacking | Steal session cookies from other users |
| Auth bypass | Access protected endpoints by smuggling requests |
| Cache poisoning | Inject malicious content into CDN caches |

---

## Prevention Checklist for AI Prompts

```
✅ HTTP SMUGGLING PREVENTION:
- Use HTTP/2 or HTTP/3 exclusively (immune to CL/TE smuggling)
- Reject requests with both Content-Length and Transfer-Encoding headers
- Normalize Transfer-Encoding header — only accept "chunked"
- Disable HTTP/1.1 keepalive between proxies and backends
- Use a WAF with smuggling detection
- Keep reverse proxy and backend server software updated
- For nginx: add "proxy_set_header Connection '';"
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Apache HTTP Server mod_proxy request splitting/smuggling | CVE-2023-25690 | Access-control bypass, cache poisoning (CVSS 9.8) |
| nginx error_page request smuggling | CVE-2019-20372 | WAF bypass, request injection |
| HAProxy integer-overflow request smuggling | CVE-2021-40346 | Bypass of `http-request` ACLs via smuggled request |
| Node.js llhttp Transfer-Encoding smuggling | CVE-2022-32215 | Cache poisoning / request smuggling via multi-line TE header |
| Apache Tomcat Ghostcat (AJP) | CVE-2020-1938 | AJP-based local file inclusion / potential RCE — an AJP protocol issue, not CL/TE HTTP smuggling |

---

## References

- [OWASP HTTP Request Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)
- [PortSwigger HTTP Request Smuggling Guide](https://portswigger.net/web-security/request-smuggling)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)
