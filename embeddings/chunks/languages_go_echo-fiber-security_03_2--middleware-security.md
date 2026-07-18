---
source: "languages/go/echo-fiber-security.md"
title: "🐹 Echo & Fiber Security Guide"
heading: "2. Middleware Security"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [authentication, binding, csrf, error, go, handling, language-vuln, middleware, protection, security]
chunk: 3/8
---

## 2. Middleware Security

### CVE-2024-38513 — Fiber Session Middleware Token Injection (CRITICAL)

**Severity**: CRITICAL (CVSS 10.0)
**Affected**: Fiber < v2.52.1
**Root Cause**: Session middleware allowed users to supply their own `session_id` value, enabling session fixation attacks.

```go
// VULNERABLE (Fiber < 2.52.1): Session fixation
store := session.New()

app.Get("/login", func(c *fiber.Ctx) error {
    sess, err := store.Get(c)
    if err != nil {
        panic(err)
    }
    
    // User sets cookie: session_id=attacker_controlled_id
    // ⚠️ The middleware creates a session with that ID!
    // Attacker: "I know the victim's session ID because I SET IT"
    
    sess.Set("authenticated", false)
    sess.Save()
    return c.Next()
})

// VULNERABLE EXPLOITATION:
// 1. Attacker crafts session_id=known_value
// 2. Victim opens link, gets session with known ID
// 3. Victim authenticates — session now tied to known ID
// 4. Attacker uses the known session ID to impersonate victim
```

**Fix (Fiber ≥ 2.52.1):**
```go
// SECURE: Use Fiber ≥ 2.52.1 with automatic session ID generation
store := session.New(session.Config{
    // KeyGenerator provides unique, unpredictable session IDs
    KeyGenerator: utils.UUIDv4,
})

// Always use server-generated session IDs
// Never accept user-supplied session IDs
```

**References:**
- [CVE-2024-38513 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-38513)
- [GHSA-98j2-3j3p-fw2v](https://github.com/gofiber/fiber/security/advisories/GHSA-98j2-3j3p-fw2v)
- [Miggo CVE Analysis](https://www.miggo.io/vulnerability-database/cve/CVE-2024-38513)

### CVE-2024-25124 — Fiber CORS Middleware Insecure Config (CRITICAL)

**Severity**: CRITICAL
**Affected**: Fiber < v2.52.1
**Root Cause**: CORS middleware allowed wildcard origin (`*`) with `AllowCredentials: true` — a known insecure combination.

```go
// VULNERABLE (Fiber < 2.52.1):
app.Use(cors.New(cors.Config{
    AllowOrigins:     "*",
    AllowCredentials: true,   // ⚠️ Wildcard + credentials = insecure!
    AllowMethods:     "GET,POST,PUT,DELETE",
}))

// The browser will reject this anyway, but middleware should too
// Exploitation: Attacker's site can make credentialed requests to your API
```

**Fix:**
```go
// SECURE: Explicit origins
app.Use(cors.New(cors.Config{
    AllowOrigins:     "https://app.example.com, https://admin.example.com",
    AllowCredentials: true,
    AllowMethods:     "GET,POST,PUT,DELETE",
    AllowHeaders:     "Authorization, Content-Type",
}))

// Or deny credentials when using wildcard
app.Use(cors.New(cors.Config{
    AllowOrigins:     "*",
    AllowCredentials: false,
    AllowMethods:     "GET,POST",
}))
```

**References:**
- [CVE-2024-25124 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-25124)
- [GHSA-fmg4-x8pw-hjhg](https://github.com/advisories/GHSA-fmg4-x8pw-hjhg)

### Middleware Order Security

```go
// VULNERABLE: Wrong middleware order
e := echo.New()
e.Use(middleware.CSRF())          // CSRF before rate limiting — DoS via token generation
e.Use(middleware.RateLimiter(...)) // Rate limiting after CSRF — too late
e.Use(middleware.CORS())           // CORS after everything — preflight fails
e.Use(authMiddleware)              // Auth after CORS — OK but late

// SECURE: Correct middleware order
e := echo.New()
e.Use(middleware.Logger())                     // 1. Logging
e.Use(middleware.CORSWithConfig(middleware.CORSConfig{  // 2. CORS first (preflight)
    AllowOrigins: []string{"https://app.example.com"},
    AllowMethods: []string{http.MethodGet, http.MethodPost},
}))  
e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))  // 3. Rate limit
e.Use(authMiddleware)                                                    // 4. Auth
e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{                   // 5. CSRF
    CookieSameSite: http.SameSiteLaxMode,
}))
```

### Fiber: Custom Middleware Pitfalls

```go
// VULNERABLE: Custom middleware that modifies request before auth
app.Use(func(c *fiber.Ctx) error {
    // ⚠️ Parses body without checking auth first
    var body map[string]interface{}
    json.Unmarshal(c.Body(), &body)
    
    if body["force_admin"] == true {
        c.Locals("role", "admin")  // Privilege escalation!
    }
    return c.Next()
})

// SECURE: Middleware should not trust unauthenticated input
app.Use(func(c *fiber.Ctx) error {
    // Log request, don't process body
    log.Printf("Request: %s %s", c.Method(), c.Path())
    return c.Next()
})
```

---