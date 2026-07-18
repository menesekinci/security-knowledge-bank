---
source: "languages/csharp/aspnet-data-protection.md"
title: "ASP.NET Core Data Protection API Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 10
total_chunks: 14
heading: "8. Multi-Node Deployments"
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
    .ProtectKeysWithAes();

// Option C: Network share (Windows only)
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"\\network\share\keys"))
    .ProtectKeysWithDpapi();
```

---