# 🟠 Server-Side Request Forgery (Node.js)

## What Is It?
The server makes a request to a URL controlled by the attacker.
Used to access internal services (localhost:6379 → Redis, 127.0.0.1:9200 → Elasticsearch).

## Example
```javascript
// 💀 VULNERABLE:
app.post('/fetch-url', async (req, res) => {
    const { url } = req.body;
    const response = await axios.get(url);  // Request to any URL!
    res.send(response.data);
});

// Attacker: {"url": "http://169.254.169.254/latest/meta-data/"}
// → AWS metadata endpoint → credentials leaked 💀
```

## Secure Code
```javascript
// ✅ SECURE:
const ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.example.com'];

app.post('/fetch-url', async (req, res) => {
    const { url } = req.body;
    const parsed = new URL(url);
    
    if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
        return res.status(403).send('Domain not allowed');
    }
    
    if (parsed.hostname === 'localhost' || parsed.hostname.startsWith('127.')) {
        return res.status(403).send('Internal IP blocked');
    }
    
    const Ip = await dns.promises.resolve4(parsed.hostname);
    if (isPrivateIp(Ip[0])) {
        return res.status(403).send('Private IP blocked');
    }
    
    const response = await axios.get(url, { timeout: 5000 });
    res.send(response.data);
});
```

## Prevention
- URL whitelist
- Block private IPs (10.x, 172.16-31.x, 192.168.x, 127.x)
- DNS rebinding protection (resolve IP, make request, check again)
- Timeout mandatory

---

**Severity: 🟠 High** — Internal service access.
**CWE: CWE-918**
