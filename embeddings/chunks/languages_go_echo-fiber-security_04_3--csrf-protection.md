---
source: "languages/go/echo-fiber-security.md"
title: "🐹 Echo & Fiber Security Guide"
heading: "3. CSRF Protection"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [authentication, binding, csrf, error, go, handling, language-vuln, middleware, protection, security]
chunk: 4/8
---

## 3. CSRF Protection

### Echo CSRF Config

```go
// VULNERABLE: CSRF disabled or misconfigured
e := echo.New()
// No CSRF middleware — all state-changing endpoints vulnerable!

// WEAK: CSRF with same-site=None (disables CSRF protection for cross-site)
e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
    CookieSameSite: http.SameSiteNoneMode,  // ⚠️ Disables CSRF protection!
}))

// SECURE: Proper CSRF configuration
e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
    TokenLength:    32,
    TokenLookup:    "header:X-CSRF-Token",
    ContextKey:     "csrf",
    CookieName:     "_csrf",
    CookieMaxAge:   86400,
    CookieSameSite: http.SameSiteLaxMode,  // Good balance of security + UX
    // For high-security: http.SameSiteStrictMode
}))

// SECURE: For API endpoints, use token-based auth (no CSRF needed)
api := e.Group("/api")
api.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
    KeyLookup: "header:Authorization",
    Validator: func(key string, c echo.Context) (bool, error) {
        return validateAPIKey(key), nil
    },
}))
```

### Fiber CSRF Config

```go
// VULNERABLE: No CSRF protection
app.Post("/transfer", func(c *fiber.Ctx) error {
    // State-changing operation without CSRF check
    amount := c.Params("amount")
    to := c.Params("to")
    return transferFunds(c, amount, to)
})

// SECURE: Fiber CSRF middleware
app.Use(csrf.New(csrf.Config{
    KeyLookup:      "header:X-CSRF-Token",
    CookieName:     "csrf_",
    CookieSameSite: "Lax",
    Expiration:     1 * time.Hour,
    KeyGenerator:   utils.UUID,  // Use cryptographically secure generator
}))

// IMPORTANT: CSRF middleware must be BELOW CORS middleware
// to handle preflight OPTIONS requests
```

---