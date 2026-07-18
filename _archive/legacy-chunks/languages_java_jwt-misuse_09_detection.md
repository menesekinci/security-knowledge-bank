---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
category: "language-vuln"
language: "java"
chunk: 9
total_chunks: 10
heading: "Detection"
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