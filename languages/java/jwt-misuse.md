# JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls

## Overview

JSON Web Tokens (JWTs) are the de facto standard for authentication and authorization in modern Java web applications. Java has mature JWT libraries (JJWT 0.12+, Nimbus JOSE+JWT, Auth0 java-jwt), but their APIs leave room for critical security mistakes. AI-generated Java code makes the same JWT errors consistently:

1. **Algorithm confusion** — Accepting `alg: "none"` or mixing HMAC and RSA
2. **Weak signing keys** — Hardcoded, short, or guessable secrets
3. **No expiration validation** — Tokens live forever
4. **Claim injection** — Overwriting critical claims in untrusted input

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

## AI-Generated Vulnerability: Using JWT for Session Management

JWT is frequently recommended by AI as a "better session token" — but this is often the wrong approach:

```java
// AI-GENERATED — uses JWT as long-lived session token
// Problems: no way to revoke, can't invalidate on logout, token stolen = permanent access
```

**Best practice**: Use opaque session identifiers (server-side sessions) for web apps. Reserve JWT for API-to-API authentication with short expiration and refresh token rotation.

## Real CVEs

- **CVE-2022-21449 (Psychic Signatures in Java)**: CVSS 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`) — A flaw in the JDK's ECDSA signature verification (Oracle Java SE 15–18, e.g. 17.0.2/18) meant that a blank/all-zero ECDSA signature `(r=0, s=0)` was always accepted as valid, regardless of the signed content. Any JWT library relying on the JDK for ES256/ES384/ES512 verification (Nimbus, jose4j, java-jwt) accepted forged tokens until the JDK was patched.
- **CVE-2023-52428 (Nimbus JOSE+JWT)**: CVSS 7.5 (`...S:U/C:N/I:N/A:H`) — Denial of service in Connect2id Nimbus JOSE+JWT before 9.37.2: an attacker supplies a JWE with a very large PBES2 `p2c` (PBKDF2 iteration count) header, forcing the `PasswordBasedDecrypter` into excessive CPU consumption.
- **CVE-2023-51775 (jose4j)**: CVSS 6.5 (`...PR:L/UI:N/S:U/C:N/I:N/A:H`) — The same class of PBES2 abuse in jose4j before 0.9.4: a large `p2c` (PBES2 Count) value causes a CPU-consumption denial of service.

## Detection

```bash
# Check for algorithm confusion vulnerabilities
grep -r "parseClaimsJws\|parseSignedClaims" src/

# Check for hardcoded JWT secrets
grep -r '"secret"\|"jwt-secret"\|JWT_SECRET' src/

# Check for no-expiration token creation
grep -r 'Jwts.builder' src/ | grep -v 'expiration'
```

## Prevention Checklist

1. **Always enforce `requireSignature()`** — Reject `alg: none` tokens.
2. **Use strong keys** — Minimum 256-bit secret for HMAC; 2048-bit RSA; use P-256 for EC.
3. **Store secrets in vault** — Never hardcode JWT secrets in source code.
4. **Always set and check expiration** — Use 15-minute access tokens, longer-lived refresh tokens.
5. **Validate `aud` and `iss` claims** — Ensure the token is for your application.
6. **Use `jjwt` 0.12+, `nimbus-jose-jwt` 9.37.2+, or `jose4j` 0.9.4+** — Latest versions have algorithm-confusion protections and the PBES2 DoS fixes; run on a patched JDK to avoid CVE-2022-21449.
7. **Use short-lived access tokens + refresh tokens** — Minimizes impact of token theft.
8. **Avoid storing sensitive data in JWT** — Payload is base64-encoded, not encrypted (unless using JWE).
9. **Implement token revocation** — Server-side blocklist for compromised tokens.
10. **Use JWE for sensitive claims** — Encrypted JWTs if you must include PII.
