---
source: "languages/go/echo-fiber-security.md"
title: "🐹 Echo & Fiber Security Guide"
heading: "5. Authentication & JWT"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [authentication, binding, csrf, error, go, handling, language-vuln, middleware, protection, security]
chunk: 6/8
---

## 5. Authentication & JWT

```go
// VULNERABLE: Weak JWT validation
func jwtMiddleware(c echo.Context) error {
    token := c.Request().Header.Get("Authorization")
    // ⚠️ No "Bearer " prefix check — accepts any format
    // ⚠️ No signature verification
    // ⚠️ No expiration check
    
    claims := &jwt.MapClaims{}
    jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
        // ⚠️ Does not validate signing algorithm!
        // "alg": "none" attack possible!
        return []byte("secret"), nil
    })
    
    c.Set("user", claims)
    return c.Next()
}

// SECURE: Proper JWT middleware
func secureJWTMiddleware(c echo.Context) error {
    authHeader := c.Request().Header.Get("Authorization")
    if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
        return c.JSON(http.StatusUnauthorized, ErrorResponse("Missing or invalid token"))
    }
    
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    
    token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
        // CRITICAL: Validate signing algorithm
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(os.Getenv("JWT_SECRET")), nil
    })
    
    if err != nil || !token.Valid {
        return c.JSON(http.StatusUnauthorized, ErrorResponse("Invalid token"))
    }
    
    claims, ok := token.Claims.(*CustomClaims)
    if !ok {
        return c.JSON(http.StatusInternalServerError, ErrorResponse("Invalid claims"))
    }
    
    c.Set("user_id", claims.UserID)
    c.Set("user_role", claims.Role)
    return c.Next()
}
```

---