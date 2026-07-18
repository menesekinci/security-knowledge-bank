---
source: "languages/csharp/aspnet-data-protection.md"
title: "ASP.NET Core Data Protection API Deep Dive"
heading: "6. Purpose Strings — Cryptographic Isolation"
category: "language-vuln"
language: "csharp"
severity: "critical"
tags: [csharp, cve-2026-40372, data, encryption, language-vuln, management, overview, ring]
chunk: 8/14
---

## 6. Purpose Strings — Cryptographic Isolation

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — Same purpose for different payloads
public class AuthService
{
    private readonly IDataProtectionProvider _provider;
    
    public AuthService(IDataProtectionProvider provider)
    {
        // 💀 Using same purpose for cookies AND tokens
        _provider = provider;
    }
    
    public string ProtectCookie(string cookieValue)
    {
        return _provider.CreateProtector("Auth").Protect(cookieValue);
    }
    
    public string ProtectToken(string tokenValue)
    {
        // 💀 Same purpose = same key derivation!
        // Anyone who can create a valid cookie can create a valid token
        return _provider.CreateProtector("Auth").Protect(tokenValue);
    }
}
```

**Secure Code:**
```csharp
// ✅ SECURE — Unique purpose strings for isolation
public class AuthService
{
    private readonly IDataProtector _cookieProtector;
    private readonly IDataProtector _tokenProtector;
    
    public AuthService(IDataProtectionProvider provider)
    {
        // ✅ Different purposes = different derived keys
        _cookieProtector = provider.CreateProtector("Auth.Cookies.v1");
        _tokenProtector = provider.CreateProtector("Auth.Tokens.v1");
    }
    
    public string ProtectCookie(string cookieValue)
    {
        return _cookieProtector.Protect(cookieValue);
    }
    
    public string ProtectToken(string tokenValue)
    {
        return _tokenProtector.Protect(tokenValue);
    }
}

// ✅ Purpose chaining for sub-purposes
var userScopeProtector = provider
    .CreateProtector("Payments")
    .CreateProtector($"User:{userId}");
```

---