---
source: "common/http-headers-security.md"
title: "HTTP Security Headers — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy"
heading: "The Essential Security Headers"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [additional, common-vuln, essential, header, important, priority, vibe, what]
chunk: 4/10
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