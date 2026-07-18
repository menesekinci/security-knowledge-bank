---
source: "common/deserialization.md"
title: "Insecure Deserialization — Pickle, YAML, Java Serialization, JSON Attacks"
heading: "Python Pickle Deserialization"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, deserialization, java, pickle, python, vibe, what, yaml]
chunk: 4/10
---

## Python Pickle Deserialization

Pickle is **inherently unsafe** — it was designed to serialize Python objects, including functions and classes.

### Vulnerable Code

```python
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/load_data')
def load_data():
    # 🔴 VULNERABLE: loading pickle from user input
    data = request.args.get('data')
    obj = pickle.loads(bytes.fromhex(data))  # Arbitrary code execution!
    return str(obj)

# Even worse: loading from file upload
@app.route('/upload_model')
def upload_model():
    model_file = request.files['model']
    model = pickle.load(model_file)  # 🔴 VULNERABLE
    return 'Model loaded'
```

### Malicious Payload Example

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        # This executes when deserialized
        return (os.system, ('rm -rf /',))

# Attacker creates payload
payload = pickle.dumps(Exploit())
# Send payload.hex() to the vulnerable endpoint
```

### Fixed Code

```python
# ✅ SAFE: avoid pickle entirely for untrusted data
# Use JSON or other data-only serialization
import json

@app.route('/load_data')
def load_data():
    data = request.args.get('data')
    # JSON is safe — can only represent data, not objects
    obj = json.loads(data)
    return str(obj)

# ✅ If you MUST use pickle, verify integrity with HMAC
import hmac
import pickle

SECRET_KEY = os.environ.get('PICKLE_SECRET')

def secure_pickle_dumps(obj):
    data = pickle.dumps(obj)
    sig = hmac.new(SECRET_KEY.encode(), data, 'sha256').hexdigest()
    return sig + ':' + data.hex()

def secure_pickle_loads(signed_payload):
    sig, data = signed_payload.split(':', 1)
    expected = hmac.new(SECRET_KEY.encode(), bytes.fromhex(data), 'sha256').hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError('Tampered payload')
    return pickle.loads(bytes.fromhex(data))
```

---