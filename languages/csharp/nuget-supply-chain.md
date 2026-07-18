# 🔴 NuGet Supply Chain

### What Is It?
The risk of typo-squatting, dependency confusion, and malicious packages in NuGet packages.

## Example
```xml
<!-- 💀 What the AI suggested (typo-squatting — note the MISSPELLED name): -->
<PackageReference Include="Newtonsoft.JSON" Version="13.0.1" />   <!-- wrong casing / lookalike -->
<PackageReference Include="Newtonsofts.Json" Version="13.0.1" /> <!-- extra 's' -->
<PackageReference Include="Newtonsoft.Jsan" Version="13.0.1" />  <!-- transposed letters -->
<!-- A malicious package published under a lookalike name executes on restore/build. -->

<!-- ✅ SECURE — the genuine package, exact spelling, pinned version: -->
<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
<!-- Verify the exact package id + author, pin the version, use the latest stable release -->
```

## Prevention
- Keep NuGet audit on — it runs automatically during `dotnet restore` (NuGet 6.8+ / .NET 8+); there is no standalone `nuget audit` command. Review findings from `dotnet list package --vulnerable`.
- Whitelist package sources (`nuget.config`)
- Pin versions (do NOT use floating versions)
- `Version` is mandatory in `PackageReference`

---

**Severity: 🔴 Critical** — RCE.
