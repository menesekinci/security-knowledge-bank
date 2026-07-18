---
source: "common/ssrf.md"
title: "Server-Side Request Forgery (SSRF)"
heading: "Fixed Code Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [cloud, code, common-vuln, fixed, metadata, vibe, vulnerable, what]
chunk: 5/10
---

## Fixed Code Examples

**Node.js — Fixed**
```javascript
const axios = require('axios');
const { URL } = require('url');
const ip = require('ip');

// ✅ Blocklist of dangerous IPs/ranges
const BLOCKED_IPS = [
    '127.0.0.0/8',      // localhost
    '10.0.0.0/8',       // private
    '172.16.0.0/12',    // private
    '192.168.0.0/16',   // private
    '169.254.0.0/16',   // link-local (AWS metadata)
    '::1',              // IPv6 localhost
    'fc00::/7',         // IPv6 private
];

app.get('/fetch-profile', async (req, res) => {
    const imageUrl = req.query.url;

    // ✅ Validate URL format
    let parsedUrl;
    try {
        parsedUrl = new URL(imageUrl);
    } catch {
        return res.status(400).send('Invalid URL');
    }

    // ✅ Only allow HTTP/HTTPS
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return res.status(400).send('Invalid protocol');
    }

    // ✅ Resolve and check IP
    const resolvedIp = await dnsLookup(parsedUrl.hostname);
    if (isPrivateIP(resolvedIp)) {
        return res.status(403).send('Access denied');
    }

    // ✅ Don't follow redirects automatically
    const response = await axios.get(imageUrl, {
        maxRedirects: 0,
        timeout: 5000
    });
    res.send(response.data);
});
```

**Python — Fixed**
```python
import requests
from urllib.parse import urlparse
import socket

ALLOWED_HOSTS = ['avatars.cdn.com', 'images.storage.com']

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    parsed = urlparse(url)

    # ✅ Protocol restriction
    if parsed.scheme not in ('http', 'https'):
        return 'Invalid protocol', 400

    # ✅ Hostname allowlist
    if parsed.hostname not in ALLOWED_HOSTS:
        return 'Host not allowed', 403

    # ✅ Resolve and check for private IP
    try:
        ip = socket.gethostbyname(parsed.hostname)
        if ip.startswith(('10.', '172.', '192.168.', '127.', '169.254.')):
            return 'Access denied', 403
    except socket.gaierror:
        return 'Invalid host', 400

    # ✅ Timeout (don't hang on internal services)
    resp = requests.get(url, timeout=5)
    return resp.content
```