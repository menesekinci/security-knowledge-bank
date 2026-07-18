---
source: "languages/python/pickle-rce.md"
title: "Pickle Deserialization RCE"
heading: "Secure Code Fix"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, cves, explanation, language-vuln, python, real-world, secure, vulnerability, vulnerable]
chunk: 5/8
---

## Secure Code Fix

### Fix 1: Use Safe Serialization Formats

```python
# ✅ SAFE — Use JSON or safe alternatives
import json
from flask import Flask, request

app = Flask(__name__)

@app.route('/load_state', methods=['POST'])
def load_state():
    data = request.json.get('state')
    # JSON is safe — no code execution possible
    state = json.loads(data)
    return {'status': 'loaded', 'state': str(state)}
```

### Fix 2: Use safetensors for ML Models

```python
# ✅ SAFE — Use safetensors for ML model weights
from safetensors import safe_open
from flask import Flask, request

def load_model_weights(filepath):
    """Load model weights safely — no code execution possible."""
    tensors = {}
    with safe_open(filepath, framework="pt") as f:
        for key in f.keys():
            tensors[key] = f.get_tensor(key)
    return tensors
```

### Fix 3: Use `pickle` with Integrity Verification (Defense in Depth)

```python
# ✅ IMPROVED — HMAC verification prevents tampering
import pickle
import hmac
import hashlib

SECRET_KEY = b'super-secret-key'  # From environment variable

def safe_pickle_load(data):
    """Load pickled data only if HMAC signature is valid."""
    # Expect format: signature(32 bytes) || pickled_data
    signature = data[:32]
    payload = data[32:]
    
    expected = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Data integrity check failed")
    
    return pickle.loads(payload)  # Still risky with untrusted origin
```

### Fix 4: Restrict Available Classes

```python
# ✅ RESTRICTED — Allowlist-based unpickler
import pickle
import io

class SafeUnpickler(pickle.Unpickler):
    """Only allow safe built-in types."""
    ALLOWED = {
        'builtins.list', 'builtins.dict', 'builtins.int',
        'builtins.str', 'builtins.float', 'builtins.bytes',
        'builtins.tuple', 'builtins.set', 'builtins.bool',
        'builtins.NoneType',
    }
    
    def find_class(self, module, name):
        if f'{module}.{name}' not in self.ALLOWED:
            raise pickle.UnpicklingError(f'Class {module}.{name} is not allowed')
        return super().find_class(module, name)

def safe_load(data):
    return SafeUnpickler(io.BytesIO(data)).load()
```

---