---
source: "common/broken-auth.md"
title: "Broken Authentication & Session Management"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common, common-vuln, cves, prevention, real-world, vibe, vulnerabilities, what]
chunk: 3/7
---

## Why Vibe Coding Makes This Worse

AI-generated authentication code frequently contains subtle but critical flaws:

- **AI reimplements auth from scratch:** Instead of using battle-tested libraries, AI generates custom session management with homebrew tokens
- **JWT secrets hardcoded or weak:** AI places `jwt_secret = "secret"` in the code
- **Session tokens in URLs:** AI uses query parameters for session IDs
- **No rate limiting on login:** AI forgets to add lockout mechanisms
- **Insecure password storage:** AI uses MD5/SHA1 for passwords (see crypto.md)
- **Missing CSRF tokens:** AI generates forms without CSRF protection
- **"Remember me" done wrong:** AI implements persistent tokens without rotation

---