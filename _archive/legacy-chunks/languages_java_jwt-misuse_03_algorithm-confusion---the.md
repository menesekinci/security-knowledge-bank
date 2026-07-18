---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
category: "language-vuln"
language: "java"
chunk: 3
total_chunks: 10
heading: "Algorithm Confusion — The `alg: none` Attack"
---

## Algorithm Confusion — The `alg: none` Attack

The most infamous JWT vulnerability:

```java
// AI-GENERATED — accepts "none" algorithm
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;

public Claims parseToken(String token) {
    // BUG: JJWT before 0.12.0 accepts "alg: none" by default in some configurations
    // Attacker sends: header: {"alg": "none"}, payload: {"sub": "admin", "role": "admin"}
    return Jwts.parser()
        .build()
        .parseSignedClaims(token)  
        .getPayload();
}
```

**Exploit flow**:
1. Attacker captures a valid JWT (e.g., `eyJhbGciOiJIUzI1NiJ9...`)
2. Attacker decodes the header, changes `alg` from `HS256` to `none`
3. Attacker modifies payload claims (e.g., `"role": "admin"`)
4. Attacker removes the signature
5. Server accepts the token as valid (no signature ⇒ no verification)

**Secure Fix**:
```java
// JJWT 0.12+ requires explicit parser configuration
public Claims parseToken(String token) {
    return Jwts.parser()
        .requireSignature()  // Rejects tokens without a valid signature
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();
}

// Or with a specific algorithm enforced:
public JwtParser createParser() {
    return Jwts.parser()
        .verifyWith(secretKey)
        .require("alg", "HS256") // Only accept HS256
        .build();
}
```