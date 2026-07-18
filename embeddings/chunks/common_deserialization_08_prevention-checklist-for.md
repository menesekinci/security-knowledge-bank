---
source: "common/deserialization.md"
title: "Insecure Deserialization — Pickle, YAML, Java Serialization, JSON Attacks"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, deserialization, java, pickle, python, vibe, what, yaml]
chunk: 8/10
---

## Prevention Checklist for AI Prompts

```
✅ DESERIALIZATION REQUIREMENTS FOR THIS CODE:
- NEVER use pickle.load() on untrusted data — not even with verification (signing is defense-in-depth, not a solution)
- Use safe_load() for YAML (Python), safe_load (Ruby), or disable custom constructors
- Avoid Java ObjectInputStream — use JSON, Protocol Buffers, or FlatBuffers instead
- If Java deserialization is unavoidable, implement class allowlisting
- Never use eval() or similar for "parsing" user-supplied data
- Apply input validation BEFORE deserialization when possible
- Use HMAC signing if serialized data must traverse untrusted channels
- Prefer JSON.parse() / json.loads() for data-only formats
- Watch for prototype pollution via __proto__ during object merge/clone
- Keep serialization libraries up to date (gadget chains are discovered regularly)
```

### Serialization Safety Table

| Format | Safe? | Notes |
|---|---|---|
| JSON (standard) | ✅ Safe | Data only — no objects/functions |
| XML (parsed safely) | ✅ Safe | Avoid XSLT, DTD external entities |
| YAML (safe_load) | ✅ Safe | Only basic types |
| Pickle (Python) | ❌ NEVER | Arbitrary code execution by design |
| Java serialization | ❌ NEVER | Gadget chains enable RCE |
| PHP unserialize() | ❌ NEVER | Object injection + RCE |
| YAML (default load) | ❌ NEVER | Allows arbitrary objects |
| MessagePack | ⚠️ Conditional | Safe for data; unsafe if used with class factories |
| Protocol Buffers | ✅ Safe | Strict schema, data only |
| Avro / Thrift | ✅ Safe | Schema-based, no code execution |

---