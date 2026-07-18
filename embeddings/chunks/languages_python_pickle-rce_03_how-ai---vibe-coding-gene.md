---
source: "languages/python/pickle-rce.md"
title: "Pickle Deserialization RCE"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, cves, explanation, language-vuln, python, real-world, secure, vulnerability, vulnerable]
chunk: 3/8
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