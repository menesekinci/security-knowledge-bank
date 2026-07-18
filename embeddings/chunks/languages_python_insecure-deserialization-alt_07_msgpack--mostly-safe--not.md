---
source: "languages/python/insecure-deserialization-alt.md"
title: "Insecure Deserialization: Python Alternatives Compared"
heading: "msgpack: Mostly Safe, Not Invulnerable"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cve-2020-14343, cve-2026-24009, jsonpickle, language-vuln, library, overview, pickle, python, pyyaml, security]
chunk: 7/10
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