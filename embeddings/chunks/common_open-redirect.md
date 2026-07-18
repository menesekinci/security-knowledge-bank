---
source: "common/open-redirect.md"
title: "Open Redirect"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, dangerous, fixed, patterns, vibe, vulnerable, what]
---

# Open Redirect

**CWE:** CWE-601 (URL Redirection to Untrusted Site)
**OWASP Top 10:2021:** A01 — Broken Access Control

---

## What Is an Open Redirect?

An open redirect vulnerability occurs when an application takes a user-supplied URL and **redirects the browser to it** without validation. Attackers use this to craft convincing phishing links: legitimate-appearing URLs that redirect to malicious sites.

**The danger:** Users trust the domain they see. `https://trustedbank.com/redirect?url=https://evil.com` looks safe but sends them to the attacker's site.

## Why Vibe Coding Makes This Worse

- **AI loves flexible redirects:** "Redirect to the page the user came from" → passes `?next=` or `?returnUrl=` parameter
- **AI generates OAuth callback code:** Often redirects to `state` parameter without validation
- **AI doesn't validate URLs:** AI checks "is there a URL?" not "is this URL safe?"
- **Social login implementations:** AI generates `redirect_uri` handling without proper allowlisting

## Vulnerable Code Examples

**Node.js (Express) — Vulnerable**
```javascript
app.get('/redirect', (req, res) => {
    const target = req.query.url;
    // 🔴 VULNERABLE: redirects anywhere
    res.redirect(target);
});
// Attack: /redirect?url=https://phishing-site.com
```

**Python (Flask) — Vulnerable**
```python
@app.route('/logout')
def logout():
    next_page = request.args.get('next', '/')
    # 🔴 VULNERABLE: redirects anywhere
    return redirect(next_page)
```

**Java (Spring) — Vulnerable**
```java
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url;
}
```

**Ruby on Rails — Vulnerable**
```ruby
def redirect
  redirect_to params[:url]
end
```

## Fixed Code Examples

**Node.js (Express) — Fixed**
```javascript
const ALLOWED_REDIRECTS = ['/dashboard', '/profile', '/settings'];

app.get('/redirect', (req, res) => {
    const target = req.query.url;

    // Option 1: Allowlist
    if (!ALLOWED_REDIRECTS.includes(target)) {
        return res.status(400).send('Invalid redirect');
    }

    // Option 2: Validate relative URLs only
    if (target.startsWith('/') && !target.startsWith('//')) {
        return res.redirect(target);
    }

    // Option 3: Validate hostname
    try {
        const url = new URL(target, 'https://trusted.com');
        if (url.hostname !== 'trusted.com') {
            return res.status(400).send('Invalid redirect');
        }
        res.redirect(target);
    } catch {
        return res.status(400).send('Invalid URL');
    }
});
```

**Python (Flask) — Fixed**
```python
from urllib.parse import urlparse, urljoin

@app.route('/logout')
def logout():
    next_page = request.args.get('next', '/')

    # ✅ SAFE: only allow relative paths
    if next_page.startswith('/') and not next_page.startswith('//'):
        return redirect(next_page)

    # ✅ SAFE: validate host
    host = request.host_url.rstrip('/')
    full_url = urljoin(host, next_page)
    if urlparse(full_url).netloc == urlparse(host).netloc:
        return redirect(full_url)

    return redirect('/')
```

**Java (Spring) — Fixed**
```java
@GetMapping("/redirect")
public String redirect(@RequestParam String url, HttpServletRequest request) {
    if (url.startsWith("/") && !url.startsWith("//")) {
        return "redirect:" + url;
    }
    try {
        URI uri = new URI(url);
        String myHost = request.getServerName();
        if (myHost.equals(uri.getHost())) {
            return "redirect:" + url;
        }
    } catch (URISyntaxException e) { }
    return "redirect:/";
}
```

## Dangerous Patterns to Avoid

```javascript
// 🔴 // skips protocol validation — redirects to evil.com!
// /redirect?url=//evil.com

// 🔴 @ in URL — redirects to evil.com!
// /redirect?url=https://trusted.com@evil.com

// 🔴 javascript: protocol — executes in some parsers
// /redirect?url=javascript:alert(1)

// 🔴 Backslash interpreted as /
// /redirect?url=\evil.com

// 🔴 Unicode homoglyphs (Cyrillic 'е')
// /redirect?url=https://еvil.com
```

---

## Prevention Checklist for AI Prompts

```
✅ OPEN REDIRECT PREVENTION:
- Use an allowlist of permitted redirect URLs
- Prefer relative paths (no domain) over absolute URLs
- Never redirect to user-supplied URLs without validation
- Validate URL against trusted hostnames
- Block dangerous patterns: //, @, javascript:, backslashes
- Use positive validation (what IS allowed) not negative (what is NOT allowed)
- Display a warning page for external redirects instead of auto-redirecting
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Spring Framework — `UriComponentsBuilder` open redirect / SSRF | CVE-2024-22243 | CVSS 8.1 High. Host-validation bypass on externally supplied URLs enables redirect to attacker host or SSRF. Fixed in 5.3.32 / 6.0.17 / 6.1.4 |
| Spring Framework — open redirect / SSRF (crafted host) | CVE-2024-22262 | CVSS 8.1 High. A specially crafted URL defeats the host check in `UriComponentsBuilder`. Fixed in 5.3.34 / 6.0.19 / 6.1.6 |
| Keycloak open redirect | CVE-2024-7260 | CVSS 6.1 Medium. `referrer` / `referrer_uri` parameters redirect users to a malicious page for phishing. Fixed in 24.0.7 |
| Grafana open redirect (+ client path traversal) | CVE-2025-4123 | CVSS 6.1 Medium. Redirects users to an attacker-hosted frontend plugin. Fixed in 10.4.18 / 11.2.9 / 11.3.6 / 11.4.4 / 11.5.4 |
| Jenkins open redirect (backslash / scheme-relative) | CVE-2025-27625 | CVSS 4.3 Medium. Redirect URLs starting with `\` are treated as safe but read as scheme-relative by browsers, enabling phishing. Fixed in 2.500 / LTS 2.492.2 |

---

## References

- [OWASP Unvalidated Redirects and Forwards](https://owasp.org/www-community/vulnerabilities/Unvalidated_Redirects_and_Forwards)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Open Redirect Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
