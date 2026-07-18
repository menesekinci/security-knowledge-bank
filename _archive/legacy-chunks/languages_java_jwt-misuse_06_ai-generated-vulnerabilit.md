---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
category: "language-vuln"
language: "java"
chunk: 6
total_chunks: 10
heading: "AI-Generated Vulnerability: Claim Injection"
---

## AI-Generated Vulnerability: Claim Injection

```java
// AI-GENERATED — merges user-supplied claims into token
public String generateToken(Map<String, Object> userProvidedClaims) {
    JwtBuilder builder = Jwts.builder()
        .subject(getCurrentUser())
        .issuedAt(new Date());
    
    // BUG: User can set "sub", "iat", "exp" etc.
    userProvidedClaims.forEach(builder::claim);
    
    return builder.signWith(secretKey).compact();
}
```

**Secure Fix**: Whitelist allowed claims.
```java
private static final Set<String> ALLOWED_CLAIMS = Set.of("theme", "locale");

public String generateToken(Map<String, Object> userProvidedClaims) {
    JwtBuilder builder = Jwts.builder()
        .subject(getCurrentUser())
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + 900_000));
    
    // Only allow non-critical claims
    userProvidedClaims.forEach((key, value) -> {
        if (ALLOWED_CLAIMS.contains(key)) {
            builder.claim(key, value);
        }
    });
    
    return builder.signWith(secretKey).compact();
}
```