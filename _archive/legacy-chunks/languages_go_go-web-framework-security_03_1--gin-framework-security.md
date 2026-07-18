---
source: "languages/go/go-web-framework-security.md"
title: "Go Web Framework Security: Gin / Echo / Fiber"
category: "language-vuln"
language: "go"
chunk: 3
total_chunks: 11
heading: "1. Gin Framework Security"
---

## 1. Gin Framework Security

### 1.1 CVE-2023-26125 — Improper Input Validation (X-Forwarded-Prefix)

**CVSS:** 5.6 (Medium)  
**Affected:** gin-gonic/gin < 1.9.0  
**Description:** Gin's handling of the `X-Forwarded-Prefix` header allows an attacker to inject malicious prefixes, enabling targeted web cache poisoning and security restrictions bypass.

**Vulnerable Code:**
```go
// 💀 VULNERABLE — Gin < 1.9.0
package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    
    r.GET("/api/*path", func(c *gin.Context) {
        // 💀 Gin processes X-Forwarded-Prefix without validation
        // Attacker can send: X-Forwarded-Prefix: /../../../etc
        path := c.Param("path")
        c.String(200, path)
    })
    
    r.Run()
}
```

**Secure Code:**
```go
// ✅ SECURE — Upgrade to Gin >= 1.9.0
// AND manually sanitize path parameters
package main

import (
    "strings"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    
    r.GET("/api/*path", func(c *gin.Context) {
        path := c.Param("path")
        
        // ✅ Manual path sanitization
        cleanPath := strings.TrimPrefix(path, "/")
        cleanPath = strings.ReplaceAll(cleanPath, "..", "")
        cleanPath = strings.ReplaceAll(cleanPath, "//", "/")
        
        // ✅ Validate no path traversal
        if strings.Contains(cleanPath, "/") || strings.Contains(cleanPath, "..") {
            c.AbortWithStatus(400)
            return
        }
        
        c.String(200, cleanPath)
    })
    
    r.Run()
}
```

**Source:**
- https://nvd.nist.gov/vuln/detail/cve-2023-26125
- https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMGINGONICGIN-3324285

### 1.2 Binding without Validation

**Vulnerable Code:**
```go
// 💀 VULNERABLE — Direct binding without validation
type CreateUserRequest struct {
    Username string `json:"username"`
    Role     string `json:"role"`     // 💀 Can be set to "admin"
}

func createUser(c *gin.Context) {
    var req CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // 💀 Mass assignment — user can set their own role
    user := User{Username: req.Username, Role: req.Role}
    db.Create(&user)
    
    c.JSON(200, user)
}
```

**Secure Code:**
```go
// ✅ SECURE — Separate request/response models with validation
type CreateUserRequest struct {
    Username string `json:"username" binding:"required,min=3,max=30"`
    Email    string `json:"email" binding:"required,email"`
    // ❌ No Role field — force on server side
}

type CreateUserResponse struct {
    ID       uint   `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
    // ❌ Role not included in response
}

func createUser(c *gin.Context) {
    var req CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Validation failed"})
        return
    }
    
    user := User{
        Username: req.Username,
        Email:    req.Email,
        Role:     "user",  // ✅ Force safe default
    }
    db.Create(&user)
    
    c.JSON(200, CreateUserResponse{
        ID:       user.ID,
        Username: user.Username,
        Email:    user.Email,
    })
}
```

### 1.3 Missing CSRF Protection

**Vulnerable Code:**
```go
// 💀 VULNERABLE — No CSRF protection
func main() {
    r := gin.Default()
    
    r.POST("/transfer", func(c *gin.Context) {
        // 💀 Accepts cross-origin POST — no CSRF token!
        toAccount := c.PostForm("to_account")
        amount := c.PostForm("amount")
        executeTransfer(c.GetString("user_id"), toAccount, amount)
        c.String(200, "OK")
    })
}
```

**Secure Code:**
```go
// ✅ SECURE — CSRF protection with gin-contrib/csrf
import (
    "github.com/gin-contrib/csrf"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    
    // ✅ CSRF middleware
    r.Use(csrf.Middleware(csrf.Options{
        Secret: os.Getenv("CSRF_SECRET"),
        ErrorFunc: func(c *gin.Context) {
            c.JSON(403, gin.H{"error": "CSRF token mismatch"})
            c.Abort()
        },
    }))
    
    r.GET("/csrf-token", func(c *gin.Context) {
        c.JSON(200, gin.H{"token": csrf.GetToken(c)})
    })
    
    r.POST("/transfer", func(c *gin.Context) {
        // ✅ CSRF token validated by middleware
        executeTransfer(c.GetString("user_id"), c.PostForm("to_account"), c.PostForm("amount"))
        c.String(200, "OK")
    })
}
```

---