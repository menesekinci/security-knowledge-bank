---
source: "languages/csharp/aspnet-data-protection.md"
title: "ASP.NET Core Data Protection API Deep Dive"
heading: "3. Key Ring — Multiple Application Sharing"
category: "language-vuln"
language: "csharp"
severity: "critical"
tags: [csharp, cve-2026-40372, data, encryption, language-vuln, management, overview, ring]
chunk: 5/14
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