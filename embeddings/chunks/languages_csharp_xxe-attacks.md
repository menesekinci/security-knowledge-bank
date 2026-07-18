---
source: "languages/csharp/xxe-attacks.md"
title: "🟠 C# XXE Attacks"
category: "language-vuln"
language: "csharp"
severity: "high"
tags: [csharp, dangerous, example, language-vuln, prevention]
---

# 🟠 C# XXE Attacks

## Example (Dangerous)
```csharp
// 💀 VULNERABLE:
XmlDocument doc = new XmlDocument();
doc.LoadXml(userInput);  // DTD processing enabled → XXE!

// ✅ SECURE:
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null;  // Disable external entities!

// .NET Framework 4.5.2+:
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;  // Disable DTD entirely
settings.XmlResolver = null;
using (XmlReader reader = XmlReader.Create(new StringReader(userInput), settings))
{
    doc.Load(reader);
}
```

## Prevention
- Set `DtdProcessing = Prohibit`
- Set `XmlResolver = null`
- .NET Core 3.0+: `XmlDocument.XmlResolver` defaults to null (secure)
- Protect `XPathDocument` and `XDocument` the same way

---

**Severity: 🟠 High** — SSRF, LFI.
