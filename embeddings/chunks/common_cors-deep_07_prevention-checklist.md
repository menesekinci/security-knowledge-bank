---
source: "common/cors-deep.md"
title: "CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs"
heading: "Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [coding, common-vuln, cors, headers, vibe, vulnerability, what]
chunk: 7/10
---

## Prevention Checklist

```
✅ CORS SECURITY CHECKLIST:
- Never use Access-Control-Allow-Origin: * in production
- Never reflect the Origin header without validation
- Use exact-match origin whitelisting (not regex, not suffix matching)
- Never whitelist 'null' in production
- Always require HTTPS origins (no http:// in production)
- Add Vary: Origin header when using dynamic ACAO
- Set specific Access-Control-Allow-Methods (GET, POST, etc.)
- Set specific Access-Control-Allow-Headers
- Keep Access-Control-Max-Age reasonable (10 min max)
- Do NOT rely on CORS for CSRF protection — use anti-CSRF tokens
- Implement server-side authorization — CORS is client-side only
- Never use Accept-All origins with credentials enabled
- Audit CORS headers regularly (use cors-test tool)
- For internal apps: still validate origins — don't trust network boundary
```

---