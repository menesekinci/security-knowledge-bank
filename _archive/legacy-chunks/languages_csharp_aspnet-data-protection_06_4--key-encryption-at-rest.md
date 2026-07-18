---
source: "languages/csharp/aspnet-data-protection.md"
title: "ASP.NET Core Data Protection API Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 6
total_chunks: 14
heading: "4. Key Encryption at Rest"
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
    .ProtectKeysWithAes()                                // ✅ AES encryption
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