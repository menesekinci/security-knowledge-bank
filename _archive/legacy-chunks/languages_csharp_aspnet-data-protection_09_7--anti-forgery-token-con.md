---
source: "languages/csharp/aspnet-data-protection.md"
title: "ASP.NET Core Data Protection API Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 9
total_chunks: 14
heading: "7. Anti-Forgery Token Configuration"
---

## 7. Anti-Forgery Token Configuration

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — Anti-forgery tokens without Data Protection
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";      // OK
    options.Cookie.SecurePolicy = CookieSecurePolicy.None;  // 💀 HTTP!
    options.Cookie.HttpOnly = true;
});
```

**Secure Code:**
```csharp
// ✅ SECURE — Anti-forgery with proper Data Protection backing
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;  // ✅ HTTPS only
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.IsEssential = true;
    
    // ✅ Data Protection automatically backs antiforgery tokens
});

// ✅ Validate antiforgery tokens on all POST/PUT/DELETE
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});
```

---