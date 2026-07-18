---
source: "languages/csharp/aspnet-auth-deep.md"
title: "ASP.NET Core Authentication Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 7
total_chunks: 12
heading: "5. Authorization Policy Misconfiguration"
---

## 5. Authorization Policy Misconfiguration

### Fallback Policy

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — No fallback policy — unannotated endpoints are open
builder.Services.AddAuthorization();

// Controller without [Authorize]
public class AdminController : Controller
{
    public IActionResult Index() => View();  // 💀 Accessible to everyone!
}
```

**Secure Code:**
```csharp
// ✅ SECURE — Require authenticated users by default
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// Explicitly opt out for public endpoints
[AllowAnonymous]
public class HomeController : Controller
{
    public IActionResult Index() => View();
}
```

### Policy-Based Authorization

```csharp
// ✅ SECURE — Granular policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdmin", policy =>
        policy.RequireRole("Admin"));
    
    options.AddPolicy("CanManageUsers", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "permission" && c.Value == "users.manage") ||
            context.User.IsInRole("Admin")));
    
    options.AddPolicy("Over18", policy =>
        policy.RequireClaim("age")
              .RequireAssertion(context =>
              {
                  var ageClaim = context.User.FindFirst("age")?.Value;
                  return int.TryParse(ageClaim, out var age) && age >= 18;
              }));
});

[Authorize(Policy = "CanManageUsers")]
public class UserManagementController : Controller { }
```

---