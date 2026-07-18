---
source: "languages/csharp/deserialization.md"
title: "💠 C# Deserialization RCE"
category: "language-vuln"
language: "csharp"
severity: "critical"
tags: [binaryformatter, code, csharp, dangerous, does, example, language-vuln, secure, what]
---

# 💠 C# Deserialization RCE

## What Is It?

In .NET, deserialization is the conversion of serialized data from an untrusted source
into an object. Some deserializers, especially **BinaryFormatter**,
allow the creation of **any type** contained within the incoming data — which means RCE.

## How Does It Appear in Vibe Coding?

```
Prompt: "Write a service that reads JSON from cache"
AI: "Sure, let me use Json.NET" — correct.
But then: "Read objects with BinaryFormatter"? 💀
```

AI tends to recommend old patterns, especially in .NET Framework (not Core) projects.

## Example: Dangerous Code

```csharp
// AI's "cache reader":
public static T LoadFromCache<T>(string key)
{
    byte[] data = File.ReadAllBytes($"cache/{key}.bin");
    
    // 💀 BINARYFORMATTER — Open to RCE!
    BinaryFormatter formatter = new BinaryFormatter();
    return (T)formatter.Deserialize(new MemoryStream(data));
}

// Attacker's payload:
// Gadget chain created with ysoserial.net
// → Process.Start("cmd.exe", "/c calc.exe") executes
```

## Secure Code

```csharp
// ✅ Safe alternative — System.Text.Json
public static T LoadFromCache<T>(string key)
{
    string json = File.ReadAllText($"cache/{key}.json");
    return JsonSerializer.Deserialize<T>(json, new JsonSerializerOptions
    {
        // Strict type checking
        TypeInfoResolver = new DefaultJsonTypeInfoResolver()
    });
}

// ✅ Or with Newtonsoft.Json with type handling off:
public static T LoadFromCache<T>(string key)
{
    string json = File.ReadAllText($"cache/{key}.json");
    return JsonConvert.DeserializeObject<T>(json, new JsonSerializerSettings
    {
        TypeNameHandling = TypeNameHandling.None  // Critical!
    });
}
```

## 🔴 BinaryFormatter: Why Is It Banned?

BinaryFormatter:
- Specifies **which type** is in the serialized data (TypeNameHandling)
- An attacker can manipulate this information to load **malicious types**
- Ready-made gadget chains are available via `ysoserial.net`

**Microsoft officially declared BinaryFormatter unsafe:**
- .NET 5+: `BinaryFormatter` throws `NotSupportedException` by default
- .NET 8+: Completely removed
- Still works in .NET Framework → **migrate!**

## Prevention Methods

| What to Do? | Why? |
|-------------|------|
| Do NOT use `BinaryFormatter` | Officially declared unsafe |
| Set `JsonSerializerSettings.TypeNameHandling = None` | Don't leave type info to the client |
| If using `Newtonsoft.Json`, add `SerializationBinder` | Restrict allowed types |
| `LosFormatter`, `SoapFormatter`, `NetDataContractSerializer` are also unsafe | Don't use these either |
| DataContractSerializer is safe | But still validate input |

## Prompt Pattern for Vibe Coding
```
When doing deserialization in .NET:
- NEVER use BinaryFormatter, LosFormatter, SoapFormatter
- Use System.Text.Json (with TypeInfoResolver)
- If using Newtonsoft.Json, set TypeNameHandling=None
- Always validate incoming data (HMAC, signature, validation)
```

## Real World Examples
- **CVE-2020-1147** (CVSS 7.8, CISA KEV): RCE in .NET Framework / SharePoint / Visual Studio via **DataSet / DataTable** XML deserialization. Improper validation of the XML source markup lets a crafted document run arbitrary code in the deserializing process — the canonical .NET deserialization gadget, actively exploited against SharePoint.
- **CVE-2024-29059** (CVSS 7.5, CISA KEV): **.NET Framework information disclosure** — HTTP .NET Remoting leaks an `ObjRef` URI (e.g. via `/RemoteApplicationMetadata.rem`). It is an info-disclosure flaw (not an ASP.NET Core RCE), but the leaked ObjRef enables the classic **.NET Remoting deserialization** RCE path.
- **ysoserial.net**: Popular .NET gadget chain tool (200+ chains) for `BinaryFormatter`, `LosFormatter`, DataSet, etc.

---

**Severity: 🔴 Critical** — Remote Code Execution.
**CWE: CWE-502 (Deserialization of Untrusted Data)**
**OWASP: A08:2021 (Software and Data Integrity Failures)**
