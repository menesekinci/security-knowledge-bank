---
source: "languages/csharp/hardening-checklist.md"
title: "💠 C# / .NET Security Hardening Checklist"
category: "checklist"
language: "csharp"
severity: "medium"
tags: [checklist, code, csharp, database, general, security]
---

# 💠 C# / .NET Security Hardening Checklist

> Items to check in every .NET project before deployment.

## ✅ General
- [ ] Has `dotnet list package --vulnerable` been run?
- [ ] Are NuGet packages version pinned?
- [ ] Is BinaryFormatter, LosFormatter, SoapFormatter not used?
- [ ] Is NuGet audit enabled? (runs automatically during `dotnet restore`; NuGet 6.8+ / .NET 8+ — control via `<NuGetAudit>true</NuGetAudit>` and `<NuGetAuditLevel>` in the project/props. There is no standalone `dotnet audit` command.)

## ✅ Code Security
- [ ] Is there LINQ injection risk? (dynamic Expression tree structure)
- [ ] Is Dynamic/Reflection usage security-controlled?
- [ ] Is Regex timeout set? (ReDoS)
- [ ] Command injection check with `Process.Start()`

## ✅ ASP.NET Core
- [ ] Is CORS only open for trusted origins?
- [ ] Is `appsettings.Development.json` not used in production?
- [ ] Is the exception page (DeveloperExceptionPage) disabled in production?
- [ ] Is HSTS active? (`UseHsts()`)
- [ ] Is HTTPS redirect active? (`UseHttpsRedirection()`)
- [ ] Are Anti-forgery tokens (CSRF) active?
- [ ] Is the middleware order correct? (UseRouting -> **UseCors -> UseAuthentication -> UseAuthorization** — CORS must come *before* authentication)

## ✅ Database / EF Core
- [ ] Is `FromSqlInterpolated()` used instead of `FromSqlRaw()`?
- [ ] Is `ExecuteSqlRaw()` not used?
- [ ] LINQ injection check in Entity Framework

## ✅ API
- [ ] Is rate limiting in place? (AspNetCore.RateLimit)
- [ ] Is input validation in place? (FluentValidation, DataAnnotations)
- [ ] Is JWT authentication configured correctly?

## ✅ XML
- [ ] Has `XmlDocument.XmlResolver = null` been set?
- [ ] Has `DtdProcessing = DtdProcessing.Prohibit` been set?

## 🛡️ Vibe Coding Extra
- [ ] Has AI's use of BinaryFormatter been rejected?
- [ ] Has AI's ASP.NET config been checked? (DEBUG)
- [ ] Have AI's NuGet recommendations been verified?
