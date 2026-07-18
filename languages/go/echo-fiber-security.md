# 🐹 Echo & Fiber Security Guide

> **Category:** Languages / Go / Web Framework Security
> **Last Updated:** July 2026
> **Description:** Deep dive into Echo and Fiber framework security — binding validation, middleware security, CORS, CSRF, and framework-specific vulnerabilities. Includes CVEs and proven secure patterns.

---

## 1. Binding Validation

### Echo: Context Binding

```go
// VULNERABLE: Direct binding without validation
type UserInput struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
    Role     string `json:"role"`  // ⚠️ User can set their own role!
}

func CreateUser(c echo.Context) error {
    u := new(UserInput)
    if err := c.Bind(u); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
    }
    
    // ⚠️ u.Role is user-supplied! User can set role="admin"
    user := models.User{
        Username: u.Username,
        Email:    u.Email,
        Password: u.Password,
        Role:     u.Role,  // Mass assignment!
    }
    
    result := db.Create(&user)
    return c.JSON(http.StatusCreated, user)
}

// SECURE: Separate DTO from model, validate input
type CreateUserRequest struct {
    Username string `json:"username" validate:"required,min=3,max=50,alphanum"`
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=8,max=128"`
    // ⚠️ No Role field — role is set server-side only
}

func SecureCreateUser(c echo.Context) error {
    req := new(CreateUserRequest)
    if err := c.Bind(req); err != nil {
        return c.JSON(http.StatusBadRequest, ErrorResponse(err.Error()))
    }
    
    // Validate using go-playground/validator
    if err := c.Validate(req); err != nil {
        return c.JSON(http.StatusUnprocessableEntity, ErrorResponse(err.Error()))
    }
    
    // Map DTO to model — explicit mapping, no mass assignment
    user := models.User{
        Username: req.Username,
        Email:    req.Email,
        Password: hashPassword(req.Password),
        Role:     "user",  // Server-assigned — NEVER from user!
    }
    
    result := db.Create(&user)
    return c.JSON(http.StatusCreated, user.ToPublicJSON())
}
```

### Fiber: Body Parser

```go
// VULNERABLE: Fiber body parser without validation
type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

app.Post("/login", func(c *fiber.Ctx) error {
    req := new(LoginRequest)
    if err := c.BodyParser(req); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": err.Error()})
    }
    
    // ⚠️ No input validation — potential SQL injection, NoSQL injection
    user := db.FindUser(req.Username, req.Password)
    // ...
})

// SECURE: Fiber with go-playground validation
type SecureLoginRequest struct {
    Username string `json:"username" validate:"required,min=3,max=50"`
    Password string `json:"password" validate:"required,min=8"`
}

app.Post("/login", func(c *fiber.Ctx) error {
    req := new(SecureLoginRequest)
    if err := c.BodyParser(req); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
    }
    
    // Validate
    validate := validator.New()
    if err := validate.Struct(req); err != nil {
        return c.Status(422).JSON(fiber.Map{"error": err.Error()})
    }
    
    // SQL injection safe — use parameterized queries
    user, err := db.FindUserByUsername(req.Username)
    if err != nil || !checkPassword(req.Password, user.PasswordHash) {
        return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
    }
    
    return c.JSON(fiber.Map{"token": generateToken(user)})
})
```

### Parameterized Queries (Echo/Fiber)

```go
// VULNERABLE: SQL injection via string formatting
func GetUser(c echo.Context) error {
    id := c.Param("id")
    
    // ⚠️ SQL injection: /users/1; DROP TABLE users; --
    rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
    
    // ...
}

// SECURE: Parameterized queries
func GetUser(c echo.Context) error {
    id := c.Param("id")
    
    if !isValidUUID(id) {
        return c.JSON(http.StatusBadRequest, ErrorResponse("Invalid user ID"))
    }
    
    row := db.QueryRow("SELECT * FROM users WHERE id = $1", id)  // Parameterized!
    
    // ...
}
```

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

## 6. Echo/Fiber Security Checklist

- [ ] All bind/body parsers validate input with `validator` or equivalent
- [ ] DTOs separate from domain models (no mass assignment)
- [ ] SQL queries use parameterized placeholders (`$1`, `?`), never string formatting
- [ ] CORS restricted to specific origins (no wildcard with credentials)
- [ ] CSRF middleware enabled for session-based auth
- [ ] Rate limiting applied to auth endpoints
- [ ] Error responses are generic (no stack traces, no SQL details)
- [ ] JWT validation checks signing algorithm (`alg`)
- [ ] Session IDs are server-generated (not user-supplied)
- [ ] Middleware order: CORS → Rate Limit → Auth → CSRF
- [ ] Security headers set (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- [ ] Request body size limited with `MaxBytesReader` or Fiber's body limit config
- [ ] Fiber version ≥ 2.52.1 (CORS + session fix)
- [ ] Upload directory is outside web root
- [ ] Logging doesn't include tokens, passwords, or PII

---

## References

- [CVE-2024-38513 — Fiber Session Fixation (CVSS 10.0)](https://nvd.nist.gov/vuln/detail/CVE-2024-38513)
- [CVE-2024-25124 — Fiber CORS Wildcard (CVSS 9.8)](https://nvd.nist.gov/vuln/detail/CVE-2024-25124)
- [Echo Security Middleware Documentation](https://echo.labstack.com/middleware/)
- [Fiber Security Middleware Stack](https://docs.gofiber.io/blog/fiber-v3-security-middleware-stack/)
- [OWASP Go Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Go_Security_Cheat_Sheet.html)
- [Go Vulnerability Database](https://pkg.go.dev/golang.org/x/vuln)
- [Fiber CORS Advisory GHSA-fmg4-x8pw-hjhg](https://github.com/advisories/GHSA-fmg4-x8pw-hjhg)
- [Fiber Session Advisory GHSA-98j2-3j3p-fw2v](https://github.com/gofiber/fiber/security/advisories/GHSA-98j2-3j3p-fw2v)
