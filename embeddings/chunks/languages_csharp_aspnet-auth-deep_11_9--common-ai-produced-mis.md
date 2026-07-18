---
source: "languages/csharp/aspnet-auth-deep.md"
title: "ASP.NET Core Authentication Deep Dive"
heading: "9. Common AI-Produced Misconfigurations"
category: "language-vuln"
language: "csharp"
severity: "high"
tags: [authentication, bearer, connect, cookie, csharp, cve-2025-24070, identity, language-vuln, openid, overview]
chunk: 11/12
---

## 9. Common AI-Produced Misconfigurations

1. **`RefreshSignInAsync` on unverified user** — CVE-2025-24070 pattern
2. **Hardcoded JWT signing key** — Weak key in source code
3. **`ValidateIssuer = false` and `ValidateAudience = false`** — No token validation
4. **Excessive `ClockSkew`** — 5+ minutes allows replay attacks
5. **`CookieSecurePolicy.None`** — Auth cookie over HTTP
6. **No fallback authorization policy** — Open endpoints by default
7. **`AllowAnyOrigin()` with `AllowCredentials()`** — Illegal CORS combo
8. **Implicit flow in OIDC** — Missing PKCE and authorization code flow
9. **No `RequireExpirationTime`** — Tokens that never expire
10. **`IsEssential = false`** — Cookie consent blocking auth cookies

---