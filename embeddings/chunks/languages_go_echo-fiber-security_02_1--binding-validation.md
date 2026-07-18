---
source: "languages/go/echo-fiber-security.md"
title: "🐹 Echo & Fiber Security Guide"
heading: "1. Binding Validation"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [authentication, binding, csrf, error, go, handling, language-vuln, middleware, protection, security]
chunk: 2/8
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