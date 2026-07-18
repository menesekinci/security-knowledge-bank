---
source: "common/deserialization.md"
title: "Insecure Deserialization — Pickle, YAML, Java Serialization, JSON Attacks"
heading: "YAML Deserialization"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, deserialization, java, pickle, python, vibe, what, yaml]
chunk: 6/10
---

## YAML Deserialization

YAML's anchor/alias features and type auto-detection can execute arbitrary code.

### Vulnerable Code

**Python**
```python
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route('/config')
def load_config():
    config_str = request.args.get('yaml')
    # 🔴 VULNERABLE: yaml.load() with default Loader
    config = yaml.load(config_str, Loader=yaml.Loader)
    return str(config)

# Malicious payload:
# !!python/object/apply:os.system ["rm -rf /"]
```

**Ruby**
```ruby
require 'yaml'
# 🔴 VULNERABLE
config = YAML.load(params[:config])
```

### Fixed Code

```python
# ✅ SAFE: use safe_load (only Python dicts, lists, primitives)
@app.route('/config')
def load_config():
    config_str = request.args.get('yaml')
    config = yaml.safe_load(config_str)  # No arbitrary object creation
    return str(config)

# ✅ OR disable constructors
yaml.add_constructor('tag:yaml.org,2002:python/object', None)
yaml.add_constructor('tag:yaml.org,2002:python/object/apply', None)
```

```ruby
# ✅ SAFE: Use permitted_classes
config = YAML.safe_load(params[:config])
# Or explicitly allow only certain classes:
config = YAML.load(params[:config], permitted_classes: [Symbol])
```

---