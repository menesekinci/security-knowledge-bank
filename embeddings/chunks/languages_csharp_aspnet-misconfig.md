---
source: "languages/csharp/aspnet-misconfig.md"
title: "🟠 ASP.NET Core Misconfiguration"
category: "language-vuln"
language: "csharp"
severity: "high"
tags: [critical, csharp, dangerous, example, language-vuln, points, safe]
---

# 🟠 ASP.NET Core Misconfiguration

## Example (Dangerous)
```csharp
// 💀 VULNERABLE — Development settings in production:
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();  // Detailed error → info leak
    }
    
    app.UseCors(policy => policy.AllowAnyOrigin()  // 💀 Every domain!
                                .AllowAnyMethod()
                                .AllowAnyHeader());
    
    app.UseHttpsRedirection();  // Missing: HSTS, SSL cert validation
}
```

## Example (Safe)
```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    if (!env.IsDevelopment())
    {
        app.UseHsts();  // HTTP Strict Transport Security
    }
    
    app.UseCors(policy => policy.WithOrigins("https://trusted.com")
                                .WithMethods("GET", "POST")
                                .WithHeaders("Authorization"));
    
    app.UseAuthentication();
    app.UseAuthorization();
}
```

## Critical Points
- `appsettings.Development.json` → don't use in production
- `CORS` → `AllowAnyOrigin()` only in development
- `HSTS` → mandatory in production
- Exception page → turn off in production
- HTTPS redirect → mandatory in production

---

**Severity: 🟠 High**
