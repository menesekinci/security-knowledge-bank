---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
heading: "AI-Generated Vulnerability: Weak Secret Key"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, algorithm, confusion, java, language-vuln, overview, vulnerability]
chunk: 4/10
---

## AI-Generated Vulnerability: Weak Secret Key

```java
// AI-GENERATED — uses short, hardcoded secret
private static final String JWT_SECRET = "mySecretKey";  // BUG: Only 11 chars!

public String createToken(String username) {
    return Jwts.builder()
        .subject(username)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + 86400000))
        .signWith(new SecretKeySpec(JWT_SECRET.getBytes(), "HmacSHA256"))
        .compact();
}
```

**Problems**:
- 11 characters = ~88 bits of entropy — brute-forceable
- Hardcoded in source code — visible in Git history, decompilation
- If an attacker has one valid JWT, they can brute-force the key offline

**Secure Fix**:
```java
// Use a cryptographically strong key stored securely
@Value("${jwt.secret}")  // From environment variable or secret manager
private String jwtSecret;

public String createToken(String username) {
    // Ensure minimum key length (256 bits = 32 bytes for HS256)
    byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
    if (keyBytes.length < 32) {
        throw new IllegalStateException("JWT secret must be at least 32 bytes");
    }
    SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA256");
    
    return Jwts.builder()
        .subject(username)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + 900_000)) // 15 min
        .signWith(key)
        .compact();
}
```