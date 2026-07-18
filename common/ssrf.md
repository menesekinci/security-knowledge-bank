# Server-Side Request Forgery (SSRF)

**CWE:** CWE-918 (Server-Side Request Forgery)
**OWASP Top 10:2021:** A10 — Server-Side Request Forgery (new category)
**CWE Top 25 2024:** Trending upward — SSRF is rising in prominence with cloud-native deployments

---

## What Is SSRF?

SSRF occurs when an attacker **makes the server perform HTTP requests** to internal or external resources that the attacker controls. The attacker can:

- Access internal services (databases, Redis, cloud metadata endpoints)
- Read internal files (`file:///etc/passwd`)
- Scan internal networks bypassing firewalls
- Reach cloud provider metadata services (AWS `169.254.169.254`, GCP `metadata.google.internal`)

**The root cause:** The application fetches a URL provided by user input without validating the destination.

## Why Vibe Coding Makes This Worse

- **AI loves "fetch this URL":** AI-generated code often accepts URLs from user input for profile pictures, document previews, webhook callbacks, feed imports
- **AI doesn't validate redirects:** Follows HTTP redirects to internal IPs
- **AI doesn't restrict protocols:** Allows `file://`, `gopher://`, `dict://` protocols
- **Cloud-native defaults:** AI generates code for cloud VMs without awareness of metadata endpoints

## Vulnerable Code Examples

**Node.js (Express) — Vulnerable**
```javascript
const axios = require('axios');

app.get('/fetch-profile', async (req, res) => {
    const imageUrl = req.query.url;
    // 🔴 VULNERABLE: fetches any URL
    const response = await axios.get(imageUrl);
    res.send(response.data);
});
// Attack: /fetch-profile?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
// Returns AWS credentials from metadata endpoint!
```

**Python (Flask) — Vulnerable**
```python
import requests

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # 🔴 VULNERABLE: fetches any URL
    resp = requests.get(url)
    return resp.content
```

**Ruby on Rails — Vulnerable**
```ruby
def fetch_avatar
  url = params[:url]
  # 🔴 VULNERABLE
  response = HTTP.get(url)
  send_data response.body
end
```

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

## Cloud Metadata Endpoints to Protect

| Cloud | Metadata URL |
|---|---|
| AWS | http://169.254.169.254/latest/meta-data/ |
| GCP | http://metadata.google.internal/computeMetadata/v1/ |
| Azure | http://169.254.169.254/metadata/instance?api-version=2021-02-01 |
| DigitalOcean | http://169.254.169.254/metadata/v1.json |
| Alibaba | http://100.100.100.200/latest/meta-data/ |

**Attack pattern:** `ssrf-endpoint?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin`

---

## SSRF Defense Layers

| Layer | Defense |
|---|---|
| Protocol allowlist | Only allow `http:` / `https:` — block `file:`, `gopher:`, `dict:`, `ftp:` |
| Hostname allowlist | Only allow pre-approved domains (best) |
| IP deny list | Block private, link-local, loopback ranges |
| DNS resolution check | Resolve to IP, verify it's not internal |
| Disable redirects | Don't automatically follow 3xx redirects |
| Timeout | Set short timeouts (3-5s) |
| Rate limiting | Limit requests per user to prevent scanning |

---

## Prevention Checklist for AI Prompts

```
✅ SSRF PREVENTION:
- Never trust user-supplied URLs — validate, validate, validate
- Use an allowlist of permitted domains/hosts when possible
- Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
- Restrict protocols to HTTP/HTTPS only
- Disable HTTP redirect following
- Set short timeouts (3-5 seconds)
- Resolve DNS and verify IP is not internal
- Use a separate service/firewall for outbound HTTP requests
- Never expose metadata endpoints to application servers
- Use IMDSv2 (AWS) with session-based token
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Atlassian Jira SSRF (`makeRequest` gadget) | CVE-2019-8451 | Unauthenticated access to internal network resources |
| Grafana avatar SSRF | CVE-2020-13379 | Unauthenticated server makes HTTP requests to any URL |
| Apache Solr SSRF (`masterUrl` replication) | CVE-2021-27905 | Reach internal services via replication handler |
| MinIO SSRF | CVE-2021-21287 | AWS metadata / internal database access |
| GitLab webhook SSRF | CVE-2021-22214 | Unauthenticated requests to arbitrary internal domains |
| Capital One breach (EC2 metadata SSRF) | N/A (WAF misconfiguration incident / no single CVE) | 100M+ records exposed via IMDS credential theft |

---

## References

- [OWASP A10:2021 — SSRF](https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server-Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger SSRF Guide](https://portswigger.net/web-security/ssrf)
