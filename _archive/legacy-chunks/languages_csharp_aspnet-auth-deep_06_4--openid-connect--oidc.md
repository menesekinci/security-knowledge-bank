---
source: "languages/csharp/aspnet-auth-deep.md"
title: "ASP.NET Core Authentication Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 6
total_chunks: 12
heading: "4. OpenID Connect (OIDC) Configuration"
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