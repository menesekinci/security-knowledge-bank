---
source: "languages/csharp/aspnet-auth-deep.md"
title: "ASP.NET Core Authentication Deep Dive"
heading: "6. CORS with Authentication"
category: "language-vuln"
language: "csharp"
severity: "high"
tags: [authentication, bearer, connect, cookie, csharp, cve-2025-24070, identity, language-vuln, openid, overview]
chunk: 8/12
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