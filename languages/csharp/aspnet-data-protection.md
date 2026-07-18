# ASP.NET Core Data Protection API Deep Dive

> **Category:** C# / ASP.NET Core Security Knowledge Bank  
> **Focus:** Key management, key ring, encryption at rest, CVE-2026-40372  
> **Last Updated:** July 2026

---

## Overview

The ASP.NET Core Data Protection API is used for encrypting authentication cookies, anti-forgery tokens, and other sensitive data. Its security depends entirely on proper key management, storage, and protection. CVE-2026-40372 demonstrated that misconfigured Data Protection can lead to privilege escalation and trust compromise.

---

## 1. CVE-2026-40372 — Data Protection Cryptographic Signature Bypass

**CVSS:** 9.1 (Critical) — Elevation of Privilege  
**Affected:** ASP.NET Core Data Protection — .NET 8, 9, 10  
**Description:** An improper verification of cryptographic signature in ASP.NET Core Data Protection API allows an unauthorized attacker to elevate privileges over a network. This can break trust in authentication cookies, antiforgery tokens, and other protected payloads. Particularly severe on Linux/non-Windows deployments where key protection defaults are weaker.

**Vulnerable Configuration:**
```csharp
// Program.cs — 💀 Default Data Protection on non-Windows (vulnerable)
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))  // 💀 Keys on disk
    .SetApplicationName("MyApp");
    // 💀 No key encryption at rest!
    // On Linux, keys are unprotected by default
```

**Secure Configuration:**
```csharp
// ✅ SECURE — Data Protection with encrypted keys at rest
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))
    .ProtectKeysWithAesKeyEncryptionKey()                          // ✅ Encrypt keys at rest
    .SetApplicationName("MyApp")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));  // ✅ Key rotation
```

**Source:**
- https://nvd.nist.gov/vuln/detail/CVE-2026-40372
- https://duendesoftware.com/blog/20260422-update-guidance-for-cve-2026-40372-aspnet-data-protection
- https://socprime.com/blog/cve-2026-40372-detection/

---

## 2. Key Management — Storage Locations

### Default Key Storage

By default, ASP.NET Core stores keys in:
- **Windows:** `%LOCALAPPDATA%\ASP.NET\DataProtection-Keys\`
- **Linux/macOS:** `$HOME/.aspnet/DataProtection-Keys/`
- **Azure App Service:** `%HOME%\ASP.NET\DataProtection-Keys\`

### Insecure Key Storage

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — Keys stored in application directory (exposed with source)
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("./keys"))  
    // 💀 Relative path — keys could be deployed with app
    // 💀 No encryption on the key ring
```

**Secure Code:**
```csharp
// ✅ SECURE — Keys stored in secure location with encryption

// Option A: Azure Key Vault (recommended for Azure deployments)
builder.Services.AddDataProtection()
    .ProtectKeysWithAzureKeyVault(
        new Uri("https://myvault.vault.azure.net/keys/dataprotection/"),
        new DefaultAzureCredential())
    .PersistKeysToAzureBlobStorage(
        new Uri("https://mystorage.blob.core.windows.net/container/keys.xml"));

// Option B: Redis (distributed cache) with encryption
builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(
        ConnectionMultiplexer.Connect("redishost"),
        "DataProtection-Keys")
    .ProtectKeysWithAesKeyEncryptionKey();

// Option C: Network path with DPAPI on Windows
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"\\fileserver\share\keys"))
    .ProtectKeysWithDpapi()  // ✅ Windows-only DPAPI encryption
    .SetApplicationName("ProductionApp");
```

---

## 3. Key Ring — Multiple Application Sharing

### The Problem

Multiple applications sharing the same key directory without proper isolation can decrypt each other's payloads.

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — Two apps sharing same key ring without distinction
// App1 — Finance app
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/shared/keys"));

// App2 — Blog app
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/shared/keys"));
// 💀 Blog app can decrypt Finance app's cookies!
```

**Secure Code:**
```csharp
// ✅ SECURE — Application isolation with subdirectories + different app names

// App1 — Finance app
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/shared/keys"))
    .SetApplicationName("FinanceApp")   // ✅ Unique per app
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));

// App2 — Blog app
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/shared/keys"))
    .SetApplicationName("BlogApp")      // ✅ Different app name
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));
```

---

## 4. Key Encryption at Rest

### Platform-Specific Encryption

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — No encryption for keys at rest
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))
    .SetApplicationName("MyApp");
```

**Secure Code:**
```csharp
// ✅ SECURE — Platform-appropriate key encryption

// On Windows (recommended):
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"C:\keys"))
    .ProtectKeysWithDpapi(protectToLocalMachine: false)  // ✅ DPAPI per-user
    .SetApplicationName("MyApp");

// On Linux / Docker:
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))
    .ProtectKeysWithAesKeyEncryptionKey()                                // ✅ AES encryption
    .SetApplicationName("MyApp");
// ⚠️ ProtectKeysWithAes requires a key encryption key (KEK)
// stored separately (env variable, vault, KMS)

// With Azure Key Vault:
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/app/keys"))
    .ProtectKeysWithAzureKeyVault(/* key URI */, /* credentials */)
    .SetApplicationName("MyApp");
```

---

## 5. Key Lifetime and Rotation

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — Keys that never expire or rotate
builder.Services.AddDataProtection()
    .SetDefaultKeyLifetime(TimeSpan.MaxValue)  // 💀 Keys never expire!
    .SetApplicationName("MyApp");
```

**Secure Code:**
```csharp
// ✅ SECURE — Regular key rotation
builder.Services.AddDataProtection()
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90))  // ✅ Rotate every 90 days
    .SetApplicationName("MyApp");

// ✅ Auto-generation of new keys:
// When a key expires, a new one is automatically created
// Old keys remain valid for decryption until they are revoked
// Key ring is checked on app start and periodically
```

### Manual Key Revocation

```csharp
// ✅ SECURE — Revoke compromised keys
var keyManager = serviceProvider.GetService<IKeyManager>();

// Revoke a specific key
keyManager.RevokeKeyById(
    keyId: Guid.Parse("key-id-to-revoke"),
    revocationReason: "Key compromised — rotated immediately");

// Revoke all keys created before a date
keyManager.RevokeAllKeys(
    revocationDate: DateTimeOffset.UtcNow.AddDays(-90),
    revocationReason: "Scheduled key rotation");
```

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

## 8. Multi-Node Deployments

### Shared Key Ring

**Vulnerable Code:**
```csharp
// 💀 VULNERABLE — Different keys on each node
// Node 1:
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/local/keys"));  // 💀 Local keys only
// Node 2:
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/local/keys"));  // 💀 Different keys!
// 🚨 Cookies encrypted by Node 1 can't be decrypted by Node 2
```

**Secure Code:**
```csharp
// ✅ SECURE — Shared key ring across nodes

// Option A: Azure Blob Storage (Azure deployments)
builder.Services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(new Uri("<blob-sas-uri>"))
    .ProtectKeysWithAzureKeyVault(new Uri("<key-uri>"), new DefaultAzureCredential());

// Option B: Redis cache
builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(redisConnection, "DataProtection-Keys")
    .ProtectKeysWithAesKeyEncryptionKey();

// Option C: Network share (Windows only)
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"\\network\share\keys"))
    .ProtectKeysWithDpapi();
```

---

## 9. CVE Roundup

| CVE | CVSS | Affected | Type | Fixed In |
|-----|------|----------|------|----------|
| CVE-2026-40372 | 9.1 (Critical) | .NET 8, 9, 10 (non-Windows) | Data Protection Signature Bypass | April 2026 Updates |
| CVE-2025-55315 | 9.9 (Critical) | ASP.NET Core Kestrel (8.0, 9.0, 10.0) | HTTP Request Smuggling | Oct 2025 Updates |
| CVE-2025-24070 | 7.0 (High) | .NET 6, 8.0, 9.0 Identity | Privilege Escalation | Feb 2025 Updates |

---

## 10. Version Recommendations

| Framework | Version | Status |
|-----------|---------|--------|
| .NET 10 | 10.0.x | ✅ Latest |
| .NET 8 (LTS) | 8.0.x + April 2026 patches | ✅ Recommended |
| .NET 6 | — | ❌ End of life |

---

## 11. Common AI-Produced Misconfigurations

1. **No `ProtectKeysWith*` call** — Keys stored unencrypted (especially on Linux)
2. **Default key directory** — Keys in `$HOME/.aspnet/` with no protection
3. **`SetDefaultKeyLifetime` to `TimeSpan.MaxValue`** — Keys never rotate
4. **Same purpose string for different payload types** — Cryptographic isolation failure
5. **Local-only keys on multi-node deployments** — Nodes can't decrypt each other's payloads
6. **No `SetApplicationName`** — Default app name collides in shared key rings
7. **`CookieSecurePolicy.None` for antiforgery** — Token sent over HTTP
8. **Relative key path** — `./keys` exposed in deployment directory
9. **No key revocation process** — Can't respond to compromise
10. **DPAPI on Linux** — DPAPI is Windows-only, silently does nothing on Linux

---

## Verification / Source URLs

- CVE-2026-40372: https://nvd.nist.gov/vuln/detail/CVE-2026-40372
- Duende Software CVE-2026-40372 Analysis: https://duendesoftware.com/blog/20260422-update-guidance-for-cve-2026-40372-aspnet-data-protection
- SOC Prime CVE-2026-40372 Detection: https://socprime.com/blog/cve-2026-40372-detection/
- Microsoft Data Protection Documentation: https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/
- Key Management in ASP.NET Core: https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/
- Key Storage Providers: https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-storage-providers
- Key Encryption at Rest: https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-encryption-at-rest
