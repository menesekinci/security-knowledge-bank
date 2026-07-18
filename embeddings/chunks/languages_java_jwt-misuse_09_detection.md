---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
heading: "Detection"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, algorithm, confusion, java, language-vuln, overview, vulnerability]
chunk: 9/10
---

## Detection

```bash
# Check for algorithm confusion vulnerabilities
grep -r "parseClaimsJws\|parseSignedClaims" src/

# Check for hardcoded JWT secrets
grep -r '"secret"\|"jwt-secret"\|JWT_SECRET' src/

# Check for no-expiration token creation
grep -r 'Jwts.builder' src/ | grep -v 'expiration'
```