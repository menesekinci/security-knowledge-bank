---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
category: "language-vuln"
language: "java"
chunk: 5
total_chunks: 10
heading: "AI-Generated Vulnerability: No Expiration Validation"
---

## AI-Generated Vulnerability: No Expiration Validation

```java
// AI-GENERATED — creates a token with no expiration, or doesn't check it
public boolean validateToken(String token) {
    try {
        Jwts.parser()
            .verifyWith(secretKey)
            .build()
            .parseSignedClaims(token);
        return true;  // BUG: Token never expires!
    } catch (JwtException e) {
        return false;
    }
}
```

**Secure Fix**: Always set and enforce expiration.
```java
// Creating token — always set expiration
public String createToken(String username) {
    return Jwts.builder()
        .subject(username)
        .issuedAt(new Date())
        .notBefore(new Date())
        .expiration(new Date(System.currentTimeMillis() + 900_000)) // 15 min
        .signWith(secretKey)
        .compact();
}

// Validating — JJWT throws ExpiredJwtException automatically
// But you can also check manually:
Claims claims = Jwts.parser()
    .verifyWith(secretKey)
    .build()
    .parseSignedClaims(token)
    .getPayload();

if (claims.getExpiration().before(new Date())) {
    throw new SecurityException("Token expired");
}
```