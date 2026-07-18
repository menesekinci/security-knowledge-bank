---
source: "common/http-headers-security.md"
title: "HTTP Security Headers — HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy"
heading: "Additional Important Security Headers"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [additional, common-vuln, essential, header, important, priority, vibe, what]
chunk: 5/10
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