---
source: "common/broken-auth.md"
title: "Broken Authentication & Session Management"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common, common-vuln, cves, prevention, real-world, vibe, vulnerabilities, what]
chunk: 5/7
---

## Prevention Checklist for AI Prompts

```
✅ AUTHENTICATION REQUIREMENTS FOR THIS CODE:
- Use a well-known authentication library (Passport.js, Devise, Spring Security, django-allauth)
- Hash passwords with bcrypt (cost ≥ 12), Argon2id, or scrypt
- NEVER store passwords in plaintext, MD5, SHA1, or unsalted hashes
- NEVER hardcode secrets, API keys, or JWT secrets — use environment variables
- JWT secrets must be ≥ 256 bits and rotated regularly
- JWT tokens must have expiration (access: 15min, refresh: 7d max)
- Disable JWT 'none' algorithm — explicitly specify allowed algorithms
- Implement rate limiting on login endpoints (5 attempts per 15 min)
- Regenerate session ID on login and privilege escalation
- Set HttpOnly, Secure, SameSite=Strict on cookies
- Implement CSRF protection for all state-changing operations
- Use secure session storage (Redis, database), not in-memory
- Never expose session tokens in URLs
- Implement multi-factor authentication for sensitive operations
```

### Session Security Checklist

| Measure | Required? |
|---|---|
| HttpOnly cookie flag | ✅ Always |
| Secure cookie flag | ✅ Always (production) |
| SameSite=Strict/Lax | ✅ Always |
| Session timeout (idle + absolute) | ✅ Always |
| Session regeneration on login | ✅ Always |
| CSRF tokens on all forms | ✅ Always |
| Rate limiting on auth endpoints | ✅ Always |
| Account lockout after N failures | ✅ Always |
| Password strength enforcement | ✅ Always |

---