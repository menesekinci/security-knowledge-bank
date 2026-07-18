---
source: "languages/csharp/aspnet-data-protection.md"
title: "ASP.NET Core Data Protection API Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 5
total_chunks: 14
heading: "3. Key Ring — Multiple Application Sharing"
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