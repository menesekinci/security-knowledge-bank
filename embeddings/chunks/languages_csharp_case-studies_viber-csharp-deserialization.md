---
source: "languages/csharp/case-studies/viber-csharp-deserialization.md"
title: "CVE-2020-1147 — .NET DataSet / DataTable XML Deserialization RCE"
category: "case-study"
language: "csharp"
severity: "critical"
tags: [case-study, cause, csharp, happened, impact, root, system, target, what, when]
---

# CVE-2020-1147 — .NET DataSet / DataTable XML Deserialization RCE

## 📅 When Did It Happen?
Disclosed and patched **July 2020** (Microsoft Patch Tuesday, 14 July 2020).

## 🎯 Target System
Microsoft **.NET Framework** (2.0 – 4.8), **.NET Core** (2.1, 3.1), **Microsoft SharePoint
Server** (2010 SP2, 2013 SP1, 2016, 2019), and **Visual Studio** — any application that
deserializes untrusted XML into `DataSet` or `DataTable`.

## 🔴 What Happened?
A remote-code-execution vulnerability (**CVE-2020-1147**) was found in how .NET handles XML.
Per Microsoft: *"A remote code execution vulnerability exists in .NET Framework, Microsoft
SharePoint, and Visual Studio when the software fails to check the source markup of XML file
input."*

- `DataSet` and `DataTable` can read their contents from XML (`ReadXml`, or when they appear
  as fields inside another serialized object).
- The XML representation embeds **type information**. When reading it back, .NET would
  **instantiate arbitrary types** named in the attacker-controlled XML.
- By pointing that type information at a known **gadget chain**, an attacker turned "just
  parsing some XML" into arbitrary code execution.
- It was widely exploitable because `DataSet`/`DataTable` show up in many places developers
  don't think of as "deserialization": XML config, SOAP/WCF messages, and objects that
  themselves contain a `DataTable` field serialized via `XmlSerializer`,
  `BinaryFormatter`, `NetDataContractSerializer`, `Json.NET` with type handling, etc.

## 🧠 Root Cause
1. **Type-carrying deserialization of untrusted input**: `DataSet.ReadXml` / `DataTable`
   reconstruct objects whose types are chosen by the incoming data, not by the developer.
2. **No type allow-list**: any type resolvable in the app's loaded assemblies could be
   created and have setters/callbacks invoked → gadget chains (`ysoserial.net` ships them).
3. **Hidden reach**: even serializers that are "safe" for simple DTOs become dangerous the
   moment a `DataSet`/`DataTable` is anywhere in the object graph.

```csharp
// 💀 VULNERABLE — reconstructs attacker-chosen types from untrusted XML
var ds = new DataSet();
ds.ReadXml(new StringReader(untrustedXml));   // XML dictates which types get instantiated

// 💀 ALSO VULNERABLE — a DataTable field deserialized from an untrusted stream
[Serializable]
class Message { public DataTable Payload; }    // Payload’s XML carries type info
```

## 💥 Impact
- **Server-side RCE** wherever untrusted XML/SOAP reached a `DataSet`/`DataTable`.
- SharePoint servers were a prime target (network-reachable, XML-heavy).
- CVSS **7.8 (High)** — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`.

## 🎓 Lessons Learned
- **Never deserialize untrusted data into `DataSet`/`DataTable`** (and avoid `BinaryFormatter`,
  `LosFormatter`, `SoapFormatter`, `NetDataContractSerializer` entirely).
- **Patch**: the July 2020 update adds an **allow-list** — `DataTable.ReadXml` throws on
  disallowed types unless you explicitly opt in via `SetTypeLimiter` / documented settings.
- **Prefer `System.Text.Json`** with concrete, known DTO types and no polymorphic type handling.
- **If you must accept XML**, bind it to a fixed schema/POCO you control — never let the payload
  choose the type.
- Even `Newtonsoft.Json` is unsafe with `TypeNameHandling` set to anything but `None`.

## Vibe Coding Connection
When AI generates .NET code:
- AI may emit `DataSet.ReadXml(...)` or `BinaryFormatter` because they are old, common patterns.
- Add "do not deserialize untrusted input into DataSet/DataTable or with BinaryFormatter" to the prompt.
- Force `System.Text.Json` with explicit target types; forbid `TypeNameHandling`.

## 🔗 References
- CVE-2020-1147 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2020-1147
- Microsoft advisory: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1147
- ysoserial.net (gadget chains, educational): https://github.com/pwntester/ysoserial.net
