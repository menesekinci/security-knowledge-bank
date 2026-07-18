---
source: "languages/go/echo-fiber-security.md"
title: "🐹 Echo & Fiber Security Guide"
heading: "4. Error Handling & Information Leakage"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [authentication, binding, csrf, error, go, handling, language-vuln, middleware, protection, security]
chunk: 5/8
---

## 4. Error Handling & Information Leakage

```go
// VULNERABLE: Exposing detailed errors
app.Get("/users/:id", func(c *fiber.Ctx) error {
    id, _ := strconv.Atoi(c.Params("id"))
    user, err := db.FindUser(id)
    if err != nil {
        // ⚠️ SQL error details exposed to client!
        return c.Status(500).JSON(fiber.Map{
            "error": err.Error(),  // "ERROR: relation 'users' does not exist"
            "sql":   "SELECT * FROM users WHERE id = 1",
        })
    }
    return c.JSON(user)
})

// SECURE: Generic error messages in production
func SecureGetUser(c *fiber.Ctx) error {
    id, err := strconv.Atoi(c.Params("id"))
    if err != nil {
        return c.Status(400).JSON(fiber.Map{
            "error": "Invalid user ID",
        })
    }
    
    user, err := db.FindUser(id)
    if err != nil {
        log.Printf("User lookup error: %v", err)  // Detailed error in logs
        return c.Status(500).JSON(fiber.Map{
            "error": "Internal server error",  // Generic message to client
        })
    }
    
    return c.JSON(user.ToPublicJSON())  // Strip sensitive fields
}

// SECURE: Echo custom HTTP error handler
e.HTTPErrorHandler = func(err error, c echo.Context) {
    code := http.StatusInternalServerError
    message := "Internal server error"
    
    if he, ok := err.(*echo.HTTPError); ok {
        code = he.Code
        // Don't expose internal error details
        message = http.StatusText(code)
    }
    
    log.Printf("HTTP error: %v", err)  // Log full error
    
    if !c.Response().Committed {
        c.JSON(code, map[string]string{"error": message})
    }
}
```

---