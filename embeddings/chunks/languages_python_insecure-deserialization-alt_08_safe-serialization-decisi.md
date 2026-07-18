---
source: "languages/python/insecure-deserialization-alt.md"
title: "Insecure Deserialization: Python Alternatives Compared"
heading: "Safe Serialization Decision Tree"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cve-2020-14343, cve-2026-24009, jsonpickle, language-vuln, library, overview, pickle, python, pyyaml, security]
chunk: 8/10
---

## Safe Serialization Decision Tree

```
Is the data untrusted (user input, network)?
│
├─ YES → Can I use plain JSON?
│   ├─ YES → Use json.loads() or orjson.loads()
│   │        Add schema validation (pydantic, marshmallow)
│   │
│   └─ NO  → Can I use a schema-based binary format?
│       ├─ YES → Use Protocol Buffers, FlatBuffers, or Apache Avro
│       ├─ YES → Use msgpack with strict limits (no object_hook)
│       └─ NO  → Is XML acceptable?
│                → Use defusedxml (NOT xml.etree)
│
└─ NO (data is trusted/local only)
    ├─ pickle — acceptable ONLY for local caching/temp data
    ├─ PyYAML — use yaml.safe_load() only
    ├─ jsonpickle — NEVER use with untrusted data
    └─ msgpack — safe for RCE but limit buffer sizes
```

---