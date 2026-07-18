---
source: "languages/csharp/aspnet-data-protection.md"
title: "ASP.NET Core Data Protection API Deep Dive"
heading: "2. Key Management — Storage Locations"
category: "language-vuln"
language: "csharp"
severity: "critical"
tags: [csharp, cve-2026-40372, data, encryption, language-vuln, management, overview, ring]
chunk: 4/14
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