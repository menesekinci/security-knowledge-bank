---
source: "common/csp-deep.md"
title: "Content Security Policy (CSP) Deep — Bypass Techniques, Nonce vs Hash, Report-uri/report-to, Strict CSP"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 3/8
---

## Why Vibe Coding Makes This Worse

- **AI skips CSP entirely** — "Just add the security headers" is an afterthought prompt.
- **AI generates `unsafe-inline` by default** — "To avoid breaking scripts."
- **AI uses wildcard (`*`) in script-src** — "For CDN compatibility."
- **AI doesn't generate nonces** — Nonce-based CSP requires server-side generation that AI frameworks don't handle.
- **AI uses CDN whitelists** — Adding `https://cdnjs.cloudflare.com` to script-src opens JSONP bypass vectors.
- **AI omits `base-uri` and `object-src`** — Two directives that prevent class CSP bypasses.

---