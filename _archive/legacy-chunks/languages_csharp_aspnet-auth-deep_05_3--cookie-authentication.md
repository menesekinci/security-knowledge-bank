---
source: "languages/csharp/aspnet-auth-deep.md"
title: "ASP.NET Core Authentication Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 5
total_chunks: 12
heading: "3. Cookie Authentication Misconfiguration"
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