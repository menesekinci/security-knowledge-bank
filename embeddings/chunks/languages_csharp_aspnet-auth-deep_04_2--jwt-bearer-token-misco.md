---
source: "languages/csharp/aspnet-auth-deep.md"
title: "ASP.NET Core Authentication Deep Dive"
heading: "2. JWT Bearer Token Misconfiguration"
category: "language-vuln"
language: "csharp"
severity: "high"
tags: [authentication, bearer, connect, cookie, csharp, cve-2025-24070, identity, language-vuln, openid, overview]
chunk: 4/12
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