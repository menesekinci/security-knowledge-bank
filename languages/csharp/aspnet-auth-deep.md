# ASP.NET Core Authentication Deep Dive

> **Category:** C# / ASP.NET Core Security Knowledge Bank  
> **Focus:** Identity, JWT bearer, cookie auth, OIDC, common misconfigurations  
> **Last Updated:** July 2026

---

## Overview

ASP.NET Core offers multiple authentication schemes: Identity (cookie-based), JWT Bearer (API auth), and OpenID Connect (external providers). Misconfiguration of authentication logic is the #1 source of security vulnerabilities in ASP.NET Core applications.

---

## 1. CVE-2025-24070 — Identity RefreshSignInAsync Privilege Escalation

**CVSS:** 7.0 (High) — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H`  
**Affected:** ASP.NET Core (Microsoft.AspNetCore.Identity) — .NET 6, .NET 8.0 (≤ 8.0.13), .NET 9.0 (≤ 9.0.2), and Microsoft.AspNetCore.Identity 2.x (≤ 2.3.0)  
**Description:** A vulnerability exists in ASP.NET Core applications calling `RefreshSignInAsync` with an improperly authenticated user parameter. An attacker can invoke it with a different user than the one currently authenticated, signing into another user's account (elevation of privilege).

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — Passing unverified user to RefreshSignInAsync
public async Task<IActionResult> UpdateProfile(ProfileViewModel model)
{
    // 💀 No verification that the current user matches the target
    var user = await _userManager.FindByIdAsync(model.UserId);
    
    // Apply changes...
    user.DisplayName = model.DisplayName;
    await _userManager.UpdateAsync(user);
    
    // 💀 CVE-2025-24070: RefreshSignInAsync with potentially wrong user
    await _signInManager.RefreshSignInAsync(user);
    
    return Ok();
}
```

**Secure Code:**
```csharp
// ✅ SECURE — Verify the current user matches the target
public async Task<IActionResult> UpdateProfile(ProfileViewModel model)
{
    var currentUserId = _userManager.GetUserId(User);
    
    // ✅ Verify the current user owns this profile (or is admin)
    if (currentUserId != model.UserId && !User.IsInRole("Admin"))
    {
        return Forbid();
    }
    
    var user = await _userManager.FindByIdAsync(model.UserId);
    if (user == null) return NotFound();
    
    user.DisplayName = model.DisplayName;
    await _userManager.UpdateAsync(user);
    
    // ✅ Now safe — verified user owns the session
    await _signInManager.RefreshSignInAsync(user);
    
    return Ok();
}

// ✅ OR for admin operations — use a separate admin endpoint
[Authorize(Roles = "Admin")]
public async Task<IActionResult> AdminUpdateProfile(string userId, ProfileViewModel model)
{
    var user = await _userManager.FindByIdAsync(userId);
    if (user == null) return NotFound();
    
    user.DisplayName = model.DisplayName;
    await _userManager.UpdateAsync(user);
    await _signInManager.RefreshSignInAsync(user);
    
    return Ok();
}
```

**Source:**
- https://nvd.nist.gov/vuln/detail/cve-2025-24070
- https://github.com/dotnet/aspnetcore/issues/60871
- https://www.herodevs.com/vulnerability-directory/cve-2025-24070

---

## 2. JWT Bearer Token Misconfiguration

### Weak Signing Key

**Vulnerable Code:**
```csharp
// Program.cs — 💀 Weak or hardcoded JWT signing key
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("weakkey")   // 💀 Weak key
            ),
            ValidateIssuer = false,     // 💀 No issuer validation
            ValidateAudience = false,   // 💀 No audience validation
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(60)  // 💀 Excessive clock skew
        };
    });
```

**Secure Code:**
```csharp
// ✅ SECURE — Strong signing key with proper validation
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                // ✅ Key from secure configuration (environment variable / Key Vault)
                Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SIGNING_KEY")
                    ?? throw new InvalidOperationException("JWT signing key not configured"))
            ),
            ValidateIssuer = true,
            ValidIssuer = "https://auth.example.com",
            ValidateAudience = true,
            ValidAudience = "https://api.example.com",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1),      // ✅ Minimal clock skew
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            TokenDecryptionKey = null,                 // Ensure tokens aren't encrypted
        };
    });
```

### Algorithm Confusion Attack

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — Algorithm confusion (RS256 → HS256)
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
    // 💀 'alg: none' would also be accepted
};
```

**Secure Code:**
```csharp
// ✅ SECURE — Explicitly enforce signing algorithm
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
    AuthenticationType = "Bearer",
    // ✅ Explicit algorithm validation
    ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
    // ✅ Prevent algorithm downgrade
    TryAllIssuerSigningKeys = false,
};
```

---

## 3. Cookie Authentication Misconfiguration

### Insecure Cookie Options

**Vulnerable Code:**
```csharp
// Program.cs — 💀 Insecure cookie configuration
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.None;   // 💀 HTTP cookies
        options.Cookie.HttpOnly = false;                          // 💀 Accessible via JS
        options.Cookie.SameSite = SameSiteMode.None;             // 💀 No SameSite
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromDays(30);          // 💀 Excessive lifetime
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
    });
```

**Secure Code:**
```csharp
// ✅ SECURE — Secure cookie configuration
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;       // ✅ HTTPS only
        options.Cookie.HttpOnly = true;                                // ✅ No JS access
        options.Cookie.SameSite = SameSiteMode.Lax;                    // ✅ SameSite=Lax
        options.Cookie.IsEssential = true;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);                // ✅ Reasonable expiry
        options.SlidingExpiration = true;
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.ReturnUrlParameter = "returnUrl";
        
        // ✅ Validate returnUrl to prevent open redirect
        options.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = context =>
            {
                if (IsAjaxRequest(context.Request))
                {
                    context.Response.StatusCode = 401;
                }
                else
                {
                    var returnUrl = context.RedirectUri;
                    if (!IsLocalUrl(returnUrl))
                    {
                        returnUrl = "/";
                    }
                    context.Response.Redirect(returnUrl);
                }
                return Task.CompletedTask;
            }
        };
        
        private static bool IsLocalUrl(string url)
        {
            if (string.IsNullOrEmpty(url)) return false;
            if (url.StartsWith("/") && !url.StartsWith("//")) return true;
            if (url.StartsWith("http://") || url.StartsWith("https://")) return false;
            return false;
        }
    });
```

### Session Fixation Vulnerability

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — No session regeneration on login
public async Task<IActionResult> Login(LoginViewModel model)
{
    if (ModelState.IsValid)
    {
        var result = await _signInManager.PasswordSignInAsync(
            model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
        
        if (result.Succeeded)
        {
            // 💀 No session ID regeneration — session fixation possible
            return RedirectToLocal(model.ReturnUrl);
        }
    }
    return View(model);
}
```

**Secure Code:**
```csharp
// ✅ SECURE — ASP.NET Core Identity handles session regeneration
// (SignInManager automatically regenerates the authentication cookie)
public async Task<IActionResult> Login(LoginViewModel model)
{
    if (ModelState.IsValid)
    {
        var result = await _signInManager.PasswordSignInAsync(
            model.Email, model.Password, model.RememberMe, 
            lockoutOnFailure: true);  // ✅ Account lockout
        
        if (result.Succeeded)
        {
            // ✅ Identity automatically issues a new session cookie
            _logger.LogInformation("User logged in.");
            return RedirectToLocal(model.ReturnUrl);
        }
        
        if (result.RequiresTwoFactor)
        {
            return RedirectToPage("./LoginWith2fa");
        }
        
        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
    }
    return View(model);
}
```

---

## 4. OpenID Connect (OIDC) Configuration

### Insecure Redirect URI

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — Non-HTTPS or wildcard redirect URIs
builder.Services.AddAuthentication()
    .AddOpenIdConnect(options =>
    {
        options.ClientId = Configuration["AzureAd:ClientId"];
        options.ClientSecret = Configuration["AzureAd:ClientSecret"]; // 💀 App secrets
        options.CallbackPath = "/signin-oidc";       // Default
        options.ResponseType = "id_token";            // 💀 Implicit flow (no code exchange)
        options.SaveTokens = true;
        
        // 💀 No redirect URI validation beyond exact match
        // In Azure AD config: wildcard redirects allowed
    });
```

**Secure Code:**
```csharp
// ✅ SECURE — Proper OIDC configuration
builder.Services.AddAuthentication()
    .AddOpenIdConnect(options =>
    {
        options.ClientId = Configuration["AzureAd:ClientId"];
        options.ClientSecret = Configuration["AzureAd:ClientSecret"];
        options.CallbackPath = "/signin-oidc";
        options.ResponseType = "code";              // ✅ Authorization code flow (PKCE)
        options.UsePkce = true;                     // ✅ PKCE for public clients
        options.SaveTokens = true;
        
        // ✅ Validate all tokens
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = $"https://login.microsoftonline.com/{tenantId}/v2.0",
            ValidateAudience = true,
            ValidAudience = Configuration["AzureAd:ClientId"],
            ValidateLifetime = true,
        };
        
        // ✅ Events for security monitoring
        options.Events = new OpenIdConnectEvents
        {
            OnRemoteFailure = context =>
            {
                _logger.LogError("OIDC remote failure: {Error}", context.Failure?.Message);
                context.HandleResponse();
                context.Response.Redirect("/Account/Login");
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                _logger.LogError("OIDC auth failed: {Error}", context.Exception?.Message);
                return Task.CompletedTask;
            }
        };
    });
```

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

## 6. CORS with Authentication

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — CORS with allow all origins + credentials
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()            // 💀 Any origin
              .AllowAnyMethod()              
              .AllowCredentials();          // 💀 ILLEGAL with AllowAnyOrigin!
    });
});
```

**Secure Code:**
```csharp
// ✅ SECURE — Explicit CORS with specific origins
builder.Services.AddCors(options =>
{
    options.AddPolicy("ApiCorsPolicy", policy =>
    {
        policy.WithOrigins("https://app.example.com", "https://admin.example.com")
              .WithMethods("GET", "POST", "PUT", "DELETE", "PATCH")
              .WithHeaders("Authorization", "Content-Type")
              .SetPreflightMaxAge(TimeSpan.FromMinutes(10));
        // ❌ Do NOT call AllowCredentials() unless absolutely needed
    });
});
```

---

## 7. CVE Roundup

| CVE | CVSS | Affected | Type | Fixed In |
|-----|------|----------|------|----------|
| CVE-2025-55315 | 9.9 | ASP.NET Core Kestrel (8.0, 9.0, 10.0) | HTTP Request Smuggling | Oct 2025 Update |
| CVE-2023-33170 | 8.1 | ASP.NET Core Identity (2.1, .NET 6.0, 7.0) | Security feature bypass (account-lockout race) | .NET 7.0.8, 6.0.19 |
| CVE-2025-24070 | 7.0 | ASP.NET Core Identity (.NET 6, 8, 9) | Privilege Escalation via RefreshSignInAsync | Feb 2025 Update |
| CVE-2024-21319 | 6.8 | Microsoft.IdentityModel.JsonWebTokens | JWE token DoS (high-compression) | 7.1.2 / 6.34.0 / 5.7.0 |
| CVE-2023-36558 | 6.5 | ASP.NET Core Blazor forms | Security feature bypass (validation) | .NET 8.0, 7.0.14, 6.0.25 |

---

## 8. Version Recommendations

| Framework | Version | Status |
|-----------|---------|--------|
| .NET | 10.0.x | ✅ Latest |
| .NET 8 (LTS) | 8.0.x | ✅ Recommended for production |
| .NET 6 (EOL) | — | ❌ End of life (Nov 2024) |

---

## 9. Common AI-Produced Misconfigurations

1. **`RefreshSignInAsync` on unverified user** — CVE-2025-24070 pattern
2. **Hardcoded JWT signing key** — Weak key in source code
3. **`ValidateIssuer = false` and `ValidateAudience = false`** — No token validation
4. **Excessive `ClockSkew`** — 5+ minutes allows replay attacks
5. **`CookieSecurePolicy.None`** — Auth cookie over HTTP
6. **No fallback authorization policy** — Open endpoints by default
7. **`AllowAnyOrigin()` with `AllowCredentials()`** — Illegal CORS combo
8. **Implicit flow in OIDC** — Missing PKCE and authorization code flow
9. **No `RequireExpirationTime`** — Tokens that never expire
10. **`IsEssential = false`** — Cookie consent blocking auth cookies

---

## Verification / Source URLs

- CVE-2025-24070: https://nvd.nist.gov/vuln/detail/cve-2025-24070
- Microsoft ASP.NET Core Security: https://learn.microsoft.com/en-us/aspnet/core/security/
- ASP.NET Core Authentication: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/
- ASP.NET Core Identity: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity
- ASP.NET Core JWT Bearer: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/jwt-auth
- ASP.NET Core Authorization: https://learn.microsoft.com/en-us/aspnet/core/security/authorization/
- Auth0 — When Identity isn't enough: https://auth0.com/blog/when-aspnet-core-identity-is-no-longer-enough/
