---
source: "common/http-smuggling.md"
title: "HTTP Request Smuggling"
heading: "Fixed Configurations"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, smuggling, vibe, vulnerable, what]
chunk: 7/11
---

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