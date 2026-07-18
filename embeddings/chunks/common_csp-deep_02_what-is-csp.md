---
source: "common/csp-deep.md"
title: "Content Security Policy (CSP) Deep — Bypass Techniques, Nonce vs Hash, Report-uri/report-to, Strict CSP"
heading: "What Is CSP?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 2/8
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