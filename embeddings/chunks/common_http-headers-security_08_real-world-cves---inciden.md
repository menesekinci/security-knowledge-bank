---
source: "common/http-headers-security.md"
title: "HTTP Security Headers — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy"
heading: "Real-World CVEs & Incidents"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [additional, common-vuln, essential, header, important, priority, vibe, what]
chunk: 8/10
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