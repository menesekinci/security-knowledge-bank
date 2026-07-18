---
source: "languages/csharp/aspnet-data-protection.md"
title: "ASP.NET Core Data Protection API Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 7
total_chunks: 14
heading: "5. Key Lifetime and Rotation"
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