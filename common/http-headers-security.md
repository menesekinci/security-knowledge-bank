# HTTP Security Headers — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy

**CWE:** CWE-693 (Protection Mechanism Failure), CWE-1021 (Improper Restriction of Rendered UI Layers)
**OWASP Top 10:2021:** A05 — Security Misconfiguration
**Related:** CWE-79 (XSS), CWE-200 (Information Exposure), CWE-352 (CSRF)

---

## What Are HTTP Security Headers?

HTTP security headers are **response headers** that tell browsers how to behave when handling a web application. They provide defense-in-depth against a wide range of attacks — XSS, clickjacking, MIME-type sniffing, protocol downgrades, and information leakage.

**The problem:** These headers are almost universally missing or misconfigured in AI-generated code. They're "invisible" to developers because they don't change visible behavior — until an attack succeeds.

### Global Adoption Statistics

| Header | Adoption Rate (2024) | Trend |
|--------|---------------------|-------|
| HSTS | 25% of top 1M sites | ⬆️ Increasing |
| X-Frame-Options | 40% | ➡️ Stable |
| X-Content-Type-Options | 35% | ➡️ Stable |
| CSP | 20% | ⬆️ Increasing |
| Referrer-Policy | 18% | ⬆️ Increasing |
| Permissions-Policy | 8% | ⬆️ Growing |
| All 5+ headers | <5% | ⬆️ Slowly improving |

**Source:** https://web.dev/security-headers/

---

## Why Vibe Coding Makes This Worse

- **AI doesn't set security headers** — Headers are "ops/deployment concern," not code.
- **AI-generated app code skips middleware** — No helmet.js (Node), no secure (Python), no security middleware.
- **AI uses wildcard origins** — "To not break CORS." But weakens all other protections.
- **AI doesn't differentiate environments** — Dev config ships to production unchanged.

---

## The Essential Security Headers

### 1. HTTP Strict-Transport-Security (HSTS)

**Purpose:** Forces browsers to always connect via HTTPS, preventing SSL-stripping and man-in-the-middle attacks.

**Syntax:**
```http
Strict-Transport-Security: max-age=<expire-time>; includeSubDomains; preload
```

| Directive | Description |
|-----------|-------------|
| `max-age=31536000` | How long (seconds) to remember HSTS (1 year recommended) |
| `includeSubDomains` | Apply to all subdomains |
| `preload` | Submit to browser preload lists |

**Vulnerable — No HSTS:**
```http
# 🔴 VULNERABLE: HTTP allowed — SSL-stripping possible
# No Strict-Transport-Security header
```

**Attack Scenario (SSL-Stripping):**
```
1. User types "example.com" → HTTP (port 80)
2. Attacker on same network (WiFi) intercepts request
3. Attacker downgrades to HTTP, serves modified content
4. User never sees HTTPS — no lock icon
5. Attacker steals credentials
```

**Fixed:**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Implementation:**
```javascript
// Node.js (with helmet)
const helmet = require('helmet');
app.use(helmet.hsts({
    maxAge: 31536000,  // 1 year in seconds
    includeSubDomains: true,
    preload: true
}));

// Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

// Apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

**HSTS Preload:**
Submit your domain to https://hstspreload.org/ to be included in browser preload lists (Chrome, Firefox, Safari, Edge). Once preloaded, HTTPS is **enforced from the very first connection** — even before the first HSTS header is seen.

**⚠️ HSTS Preload Warning:** Once preloaded, it can take **months to be removed**. Ensure your entire site supports HTTPS first.

---

### 2. X-Frame-Options (Deny / SAMEORIGIN / ALLOW-FROM)

**Purpose:** Prevents clickjacking attacks by controlling whether your page can be embedded in `<frame>`, `<iframe>`, or `<object>`.

**Syntax:**
```http
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

| Value | Behavior |
|-------|----------|
| `DENY` | Cannot be framed by any page |
| `SAMEORIGIN` | Can be framed only by pages on the same origin |
| `ALLOW-FROM uri` | (Deprecated) Can be framed by specific URI |

**Vulnerable — No Protection:**
```http
# 🔴 VULNERABLE: page can be embedded in any iframe
# No X-Frame-Options header
```

**Clickjacking Attack:**
```html
<!-- Attacker's page with transparent overlay -->
<style>
  iframe { opacity: 0; position: absolute; top: 0; left: 0; z-index: 10; }
  .button { position: absolute; top: 200px; left: 100px; z-index: 5; }
</style>
<p>Click the button to win a prize!</p>
<div class="button">Click Me!</div>
<!-- Transparent iframe of bank.com/transfer positioned over the button -->
<iframe src="https://bank.com/transfer" width="500" height="500"></iframe>
```

**Fixed:**
```http
X-Frame-Options: DENY
```

**Modern Alternative — CSP `frame-ancestors`:**
```http
# ✅ Better: CSP frame-ancestors (overrides X-Frame-Options)
Content-Security-Policy: frame-ancestors 'self';
# Or for specific origins:
Content-Security-Policy: frame-ancestors https://trusted-app.com;
```

**Implementation:**
```javascript
// Node.js (with helmet)
app.use(helmet.frameguard({ action: 'deny' }));
// or
app.use(helmet.frameguard({ action: 'sameorigin' }));

// Nginx
add_header X-Frame-Options "SAMEORIGIN" always;

// Apache
Header always set X-Frame-Options "SAMEORIGIN"
```

---

### 3. X-Content-Type-Options (nosniff)

**Purpose:** Prevents MIME-type sniffing. Browsers sometimes "sniff" content by examining its actual content rather than trusting the `Content-Type` header. This can allow attackers to disguise executable scripts as images or other benign types.

**Syntax:**
```http
X-Content-Type-Options: nosniff
```

**Vulnerable — No Header:**
```http
# 🔴 VULNERABLE: Browser may ignore Content-Type
Content-Type: text/plain
# Browser might render as HTML if content looks like HTML
```

**Attack Scenario:**
```
1. Application allows file upload: profile.jpg
2. Attacker uploads file containing <script>alert(document.cookie)</script>
3. Server serves with Content-Type: image/jpeg
4. Browser ignores Content-Type, sees HTML-like content, renders as text/html
5. XSS executes
```

**Fixed:**
```http
X-Content-Type-Options: nosniff
```

**Should Be Combined With:**
```javascript
// Always set explicit Content-Type
res.setHeader('Content-Type', 'application/json');
res.setHeader('X-Content-Type-Options', 'nosniff');

// For file uploads: serve from separate domain with restrictive headers
// uploads.example.com should have:
X-Content-Type-Options: nosniff
Content-Disposition: attachment; filename="..."
Content-Type: application/octet-stream
```

---

### 4. Permissions-Policy (Formerly Feature-Policy)

**Purpose:** Controls which browser features and APIs your pages can access — camera, microphone, geolocation, notifications, etc. Replaces the legacy `Feature-Policy` header.

**Syntax:**
```http
Permissions-Policy: <directive>=<allowlist>
```

| Feature | Allowed Values | Default |
|---------|---------------|---------|
| `geolocation` | `*`, `self`, `none`, origin list | `self` |
| `camera` | `*`, `self`, `none`, origin list | `self` |
| `microphone` | `*`, `self`, `none`, origin list | `self` |
| `payment` | `*`, `self`, `none`, origin list | `self` |
| `usb` | `*`, `self`, `none`, origin list | `*` |
| `fullscreen` | `*`, `self`, `none`, origin list | `self` |
| `autoplay` | `*`, `self`, `none`, origin list | `self` |
| `clipboard-read` | `*`, `self`, `none`, origin list | `self` |
| `clipboard-write` | `*`, `self`, `none`, origin list | `self` |
| `interest-cohort` | `*`, `self`, `none`, origin list | `*` |

**Vulnerable — No Policy:**
```http
# 🔴 VULNERABLE: All features available by default
# No Permissions-Policy header
# Third-party scripts can access camera, microphone, geolocation
```

**Recommended — Strict Policy:**
```http
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=(), fullscreen=(self), autoplay=(self), clipboard-read=(self), clipboard-write=(self), interest-cohort=()
```

**Implementation:**
```javascript
// Node.js (with helmet)
app.use(helmet.permissionsPolicy({
    features: {
        geolocation: [],
        camera: [],
        microphone: [],
        payment: [],
        usb: [],
        fullscreen: ['self'],
        autoplay: ['self'],
        clipboard: ['self'],
        interestCohort: [],
    }
}));

// Nginx
add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=(), fullscreen=(self), autoplay=(self), clipboard-read=(self), clipboard-write=(self), interest-cohort=()" always;
```

**Why This Matters:**
- **Prevents data exfiltration:** Third-party scripts can't access geolocation or camera
- **Privacy compliance:** Aligns with GDPR privacy-by-default principles
- **Reduces attack surface:** Even if XSS is present, attacker can't access sensitive APIs

---

### 5. Referrer-Policy

**Purpose:** Controls how much referrer information is included in the `Referer` header when navigating from your site to another site. This prevents **referrer leakage** of sensitive URL parameters (tokens, session IDs, API keys).

**Syntax:**
```http
Referrer-Policy: <policy>
```

| Policy | Referrer Info | Description |
|--------|--------------|-------------|
| `no-referrer` | Never sent | Maximum privacy |
| `no-referrer-when-downgrade` | Only sent over HTTPS→HTTPS | Default browser behavior |
| `origin` | Only origin (no path) | Sends `https://example.com` |
| `origin-when-cross-origin` | Full URL for same-origin, origin for cross-origin | Good balance |
| `same-origin` | Full URL only for same-origin requests | Restrictive |
| `strict-origin` | Origin only over HTTPS→HTTPS | Privacy + security |
| `strict-origin-when-cross-origin` | Full same-origin, origin HTTPS→HTTPS, nothing HTTP | **Recommended** |
| `unsafe-url` | Full URL always | 🔴 Dangerous — never use |

**Vulnerable — Leaky Referrer:**
```http
# 🔴 VULNERABLE: No Referrer-Policy → browser default (full URL leakage)
# https://bank.com/transfer?token=abc123 → external site sees the token
```

**Attack Scenario:**
```
1. User visits: https://app.com/reset-password?token=eyJhbGciOiJIUzI1NiJ9
2. Page contains:
   <a href="https://analytics.example.com">Report an issue</a>
3. User clicks link. Browser sends:
   Referer: https://app.com/reset-password?token=eyJhbGciOiJIUzI1NiJ9
4. Attacker on analytics.example.com harvests the token
```

**Recommended:**
```http
Referrer-Policy: strict-origin-when-cross-origin
```

**Implementation:**
```javascript
// Node.js (with helmet)
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));

// HTML meta tag (alternative)
<meta name="referrer" content="strict-origin-when-cross-origin">

// Nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

// Apache
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

---

## Additional Important Security Headers

### 6. X-XSS-Protection (Deprecated — Do Not Use)

```http
# ⚠️ Deprecated. Modern browsers removed XSS auditor.
# Setting this can actually introduce vulnerabilities in some cases.
X-XSS-Protection: 0  # Disable (what modern browsers default to)
```

**Do NOT use X-XSS-Protection.** It was intended to prevent reflected XSS, but:
- Chrome removed it entirely (2019)
- Edge removed it (2020)
- Safari removed it (2022)
- Firefox never supported it
- Setting it to `1; mode=block` can create information leakage vulnerabilities

**Use CSP instead.**

### 7. Cache-Control (for Sensitive Pages)

```http
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache  # HTTP/1.0 backward compatibility
```

Prevents sensitive pages (dashboards, admin panels, account settings) from being stored in browser cache or intermediate proxies.

### 8. Clear-Site-Data

```http
Clear-Site-Data: "cache", "cookies", "storage"
```

Useful for logout endpoints. Clears browser data (cookies, cache, storage) when user logs out.

### 9. Cross-Origin-Resource-Policy

```http
Cross-Origin-Resource-Policy: same-site
# or: same-origin  (more restrictive)
# or: cross-origin (permissive — avoid)
```

Controls which origins can read this resource. Prevents cross-origin data leakage beyond CORS.

### 10. Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy

```http
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

Enable **cross-origin isolation**, which allows your site to use powerful features like `SharedArrayBuffer` while preventing Spectre-style attacks.

---

## Header Priority & Quick Reference

```http
# 🔴 Critical — Missing these headers exposes users to serious attacks:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff

# 🟠 Important — Missing these reduces privacy and control:
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=(), interest-cohort=()

# 🔵 Defense-in-Depth — Add these for additional security:
Content-Security-Policy: (see csp-deep.md)
Cross-Origin-Resource-Policy: same-site
Cross-Origin-Opener-Policy: same-origin
Clear-Site-Data: "cookies", "storage"  # On logout
```

---

## Prevention Checklist

```
✅ HTTP SECURITY HEADERS CHECKLIST:
- Set Strict-Transport-Security with max-age ≥ 1 year, includeSubDomains, preload
- Submit to https://hstspreload.org/ for permanent HTTPS enforcement
- Set X-Frame-Options: DENY (or SAMEORIGIN if framing on same origin needed)
- Set X-Content-Type-Options: nosniff on ALL responses
- Set Referrer-Policy: strict-origin-when-cross-origin
- Set Permissions-Policy to restrict features to only what you need
- Set Content-Security-Policy with strict directives (see csp-deep.md)
- Remove X-XSS-Protection header (deprecated, use CSP instead)
- Set Cache-Control: no-store on sensitive pages
- Add Clear-Site-Data on logout endpoints
- Use Cross-Origin-Resource-Policy for additional isolation
- Test headers: https://securityheaders.com/
- Audit headers with every deploy (CI/CD pipeline check)
- Header consistency: apply at reverse proxy/load balancer, not just app layer
- Document header decisions in a security policy file
```

---

## Real-World CVEs & Incidents

| Vulnerability | Incident | Impact |
|---------------|----------|--------|
| **BloodHound Clickjacking** | Bug bounty 2021 | Missing X-Frame-Options allowed iframing admin panel |
| **HSTS Bypass on Subdomain** | Bug bounty 2020 | Subdomain without HSTS allowed SSL-stripping |
| **Uber MIME-type XSS** | Bug bounty 2019 | Missing X-Content-Type-Options allowed script upload as image |
| **GitHub Referrer Leak** | Bug bounty 2020 | Token in URL leaked via Referrer on outbound links |
| **Slack Geofencing Bypass** | Bug bounty 2021 | Missing Permissions-Policy allowed geolocation abuse |
| **Kiwi Syslog Server Clickjacking** | CVE-2021-35237 | Missing X-Frame-Options header left the web console vulnerable to clickjacking |
| **Dropbox HSTS Preload** | Bug bounty 2018 | Missing includeSubDomains in HSTS allowed cookie theft |
| **LinkedIn Data Exfiltration** | Bug bounty 2022 | Missing Permissions-Policy allowed clipboard access |

### Case Study 1: Uber MIME-Type Sniffing XSS (2019)

Uber's asset upload system lacked `X-Content-Type-Options: nosniff`:

1. User could upload a profile picture with filename `profile.jpg`
2. Content-Type was set to `image/jpeg`
3. But the file contained `<script>alert(1)</script>` as malicious payload
4. Browser ignored Content-Type, sniffed the HTML, and rendered it as text/html
5. XSS executed when viewing the profile

**Root cause:** Missing `X-Content-Type-Options: nosniff` and server-side payload validation.

**Fix:** Added `X-Content-Type-Options: nosniff` header, implemented server-side MIME validation, and served uploads from a separate domain with `Content-Disposition: attachment`.

### Case Study 2: Github HSTS Subdomain Gap (2020)

GitHub had HSTS with `max-age` set appropriately, but certain services (pages.github.com, gist.github.com) had different `includeSubDomains` settings. This allowed SSL-stripping on specific subdomains:

1. `github.com` had Stron HSTS with `includeSubDomains`
2. But `pages.github.com` had a separate HSTS without `includeSubDomains`
3. Attacker on a shared network could SSL-strip connections to `pages.github.com`
4. User would see HTTP, not HTTPS, and think it's acceptable

**Fix:** Consistent HSTS policy across all subdomains.

### Case Study 3: LinkedIn Clipboard Data Exfiltration (2022)

LinkedIn was missing `Permissions-Policy: clipboard-read` and `clipboard-write` headers:

1. Third-party scripts loaded on LinkedIn pages could access the clipboard API
2. A malicious ad or tracking script could:
   - Read clipboard contents (potentially containing passwords, crypto addresses)
   - Write clipboard contents (could replace copied cryptocurrency addresses)
3. This was possible because the default Permissions-Policy allows clipboard access to all scripts

**Fix:** Added `Permissions-Policy: clipboard-read=(self), clipboard-write=(self)` to restrict clipboard API access.

---

## Testing Security Headers

**Using curl:**
```bash
# Check all security headers
curl -sI https://example.com | head -20

# HSTS check
curl -sI https://example.com | grep -i strict-transport

# X-Frame-Options check
curl -sI https://example.com | grep -i x-frame-options

# Full header audit
curl -s -D- https://example.com | grep -E "(Strict-Transport|X-Frame|X-Content|Referrer|Permissions|Content-Security)"
```

**Online tools:**
- [SecurityHeaders.com](https://securityheaders.com/) — Analyzes and grades your security headers (A+ target)
- [Mozilla Observatory](https://observatory.mozilla.org/) — Comprehensive security scan
- [HSTS Preload Check](https://hstspreload.org/) — Check HSTS preload status

**CI/CD integration:**
```bash
# Using npm package: lighthouse-security-headers
npx security-headers https://example.com --fail-if-below=50
```

---

## References

- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [MDN Security Headers Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [web.dev Security Headers Best Practices](https://web.dev/security-headers/)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [CWE-1021: Improper Restriction of Rendered UI Layers](https://cwe.mitre.org/data/definitions/1021.html)
- [HSTS Preload List](https://hstspreload.org/)
- [SecurityHeaders.com — Header Analyzer](https://securityheaders.com/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [Google's Web Security Best Practices](https://developers.google.com/web/fundamentals/security)
