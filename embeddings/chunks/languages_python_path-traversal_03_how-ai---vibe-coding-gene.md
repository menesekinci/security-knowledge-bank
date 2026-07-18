---
source: "languages/python/path-traversal.md"
title: "Path Traversal — Python"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

### 1. File Download/Serve Endpoints (Most Common)

```python
# 🚫 VULNERABLE — AI-generated file download
from flask import Flask, send_file
import os

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    # AI directly joins user input to base path
    filepath = os.path.join('/app/files/', filename)  # 💥
    return send_file(filepath)

# Attacker: /download?file=../../../etc/passwd
# Results in: /app/files/../../../etc/passwd → /etc/passwd
```

### 2. File Reading for Display

```python
# 🚫 VULNERABLE — AI-generated file viewer
@app.route('/read')
def read_file():
    path = request.args.get('path')
    # AI opens whatever path user provides
    content = open(path).read()  # 💥
    return f"<pre>{content}</pre>"
```

### 3. Static File Serving

```python
# 🚫 VULNERABLE — AI-generated static file serving
from flask import Flask

app = Flask(__name__)

@app.route('/static/<path:filename>')
def serve_static(filename):
    # AI expects Flask to handle security, but it doesn't
    return open(f'static/{filename}').read()  # 💥
```

### 4. Config / Settings File Loading

```python
# 🚫 VULNERABLE — AI-generated config loader
def load_config(config_name):
    import json
    # AI accepts config name from user
    with open(f'/app/configs/{config_name}.json') as f:  # 💥
        return json.load(f)
# Exploit: config_name=../../.env
# Loads: /app/configs/../../.env → /.env
```

### 5. Archive Extraction (Zip Bomb + Traversal)

```python
# 🚫 VULNERABLE — AI-generated zip extractor
import zipfile

def extract_archive(zip_path):
    with zipfile.ZipFile(zip_path, 'r') as zf:
        # AI extracts files without checking paths
        zf.extractall('/app/uploads/')  # 💥 Zip slip!
# A malicious zip can contain ../../../etc/cronjob/evil.sh
```

### Why AI Does This

- **File serving is a basic tutorial pattern:** AI training data is full of simple file servers
- **`os.path.join()` seems safe:** AI thinks joining paths prevents traversal, but absolute paths bypass it
- **No validation instinct:** AI doesn't add checks like "is the resolved path within the intended directory"
- **Training data lacks defense examples:** Most tutorials don't include path validation

---