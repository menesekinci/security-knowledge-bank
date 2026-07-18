---
source: "languages/python/pickle-rce.md"
title: "Pickle Deserialization RCE"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [code, cves, explanation, language-vuln, python, real-world, secure, vulnerability, vulnerable]
chunk: 4/8
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