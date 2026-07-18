---
source: "languages/go/go-web-framework-security.md"
title: "Go Web Framework Security: Gin / Echo / Fiber"
category: "language-vuln"
language: "go"
chunk: 5
total_chunks: 11
heading: "3. Fiber Framework Security"
---

## 3. Fiber Framework Security

### 3.1 CVE-2024-38513 — Session Middleware Token Injection (CVSS 10)

**CVSS:** 10.0 (Critical)  
**Affected:** Fiber v2 (all versions using session middleware before the fix)  
**Description:** Fiber's session middleware allows users to supply their own `session_id` value, leading to the creation of a session with that key. This enables session fixation attacks where an attacker sets a victim's session ID to one they know.

**Vulnerable Code:**
```go
// 💀 VULNERABLE — Fiber session middleware with user-supplied session ID
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/session"
)

func main() {
    app := fiber.New()
    
    store := session.New()
    
    app.Post("/login", func(c *fiber.Ctx) error {
        sess, err := store.Get(c)
        if err != nil {
            return err
        }
        
        // 💀 CVE-2024-38513: Session ID from user's cookie is accepted directly
        // If attacker sets a known session_id cookie, 
        // the session is created/used with that ID
        sess.Set("authenticated", true)
        sess.Set("user_id", "admin")
        
        if err := sess.Save(); err != nil {
            return err
        }
        
        return c.SendString("Logged in")
    })
    
    app.Listen(":3000")
}
```

**Secure Code:**
```go
// ✅ SECURE — Regenerate session ID after authentication
import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/session"
)

func main() {
    app := fiber.New()
    
    store := session.New(session.Config{
        // ✅ Enable key generation
        KeyGenerator: func() string {
            return generateRandomSessionID()  // Custom secure generator
        },
        Expiration: 8 * time.Hour,
    })
    
    app.Post("/login", func(c *fiber.Ctx) error {
        // ✅ Always get a fresh session
        sess, err := store.Get(c)
        if err != nil {
            return err
        }
        
        // ✅ Regenerate session ID on authentication
        if err := sess.Regenerate(); err != nil {
            return err
        }
        
        sess.Set("authenticated", true)
        sess.Set("user_id", c.FormValue("user_id"))
        
        if err := sess.Save(); err != nil {
            return err
        }
        
        return c.SendString("Logged in")
    })
    
    app.Listen(":3000")
}
```

**Source:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-38513
- https://github.com/gofiber/fiber/security/advisories/GHSA-98j2-3j3p-fw2v

### 3.2 Fiber Route Parameter Overflow DoS

**Vulnerable Code:**
```go
// 💀 VULNERABLE — No limit on route parameters
app.Get("/:param*", func(c *fiber.Ctx) error {
    // 💀 Extremely long routes can cause DoS
    // e.g., GET /aaaaaaaa...aaaaaaaa (10K chars)
    param := c.Params("param")
    return c.SendString(param)
})
```

**Secure Code:**
```go
// ✅ SECURE — Limit route parameter length
app.Get("/:param*", func(c *fiber.Ctx) error {
    param := c.Params("param")
    
    // ✅ Validate parameter length
    if len(param) > 1024 {
        return fiber.ErrRequestEntityTooLarge
    }
    
    return c.SendString(param)
})

// ✅ Or use middleware for global route validation
app.Use(func(c *fiber.Ctx) error {
    if len(c.Path()) > 2048 {
        return fiber.ErrRequestEntityTooLarge
    }
    return c.Next()
})
```

### 3.3 Fiber CSRF

**Vulnerable Code:**
```go
// 💀 VULNERABLE — No CSRF protection in Fiber
func main() {
    app := fiber.New()
    
    app.Post("/transfer", func(c *fiber.Ctx) error {
        // 💀 No CSRF validation
        amount := c.FormValue("amount")
        to := c.FormValue("to")
        executeTransfer(c, amount, to)
        return c.SendString("OK")
    })
}
```

**Secure Code:**
```go
// ✅ SECURE — CSRF middleware
import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/csrf"
    "github.com/gofiber/fiber/v2/utils"
)

func main() {
    app := fiber.New()
    
    // ✅ CSRF middleware
    app.Use(csrf.New(csrf.Config{
        KeyLookup:      "form:_csrf",
        CookieName:     "_csrf",
        CookieSameSite: "Strict",
        CookieSecure:   true,
        CookieHTTPOnly: true,
        Expiration:     1 * time.Hour,
        KeyGenerator:   utils.UUIDv4,
        ErrorHandler: func(c *fiber.Ctx, err error) error {
            return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
                "error": "CSRF token mismatch",
            })
        },
    }))
    
    // ✅ CSRF token endpoint
    app.Get("/csrf-token", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "token": c.Locals("csrf"),
        })
    })
    
    app.Post("/transfer", func(c *fiber.Ctx) error {
        // ✅ CSRF validated
        return c.SendString("OK")
    })
}
```

---