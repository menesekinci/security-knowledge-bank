---
source: "languages/python/insecure-deserialization-alt.md"
title: "Insecure Deserialization: Python Alternatives Compared"
heading: "jsonpickle: Pickle in JSON Clothing"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [cve-2020-14343, cve-2026-24009, jsonpickle, language-vuln, library, overview, pickle, python, pyyaml, security]
chunk: 6/10
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