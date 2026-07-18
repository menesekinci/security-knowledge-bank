---
source: "languages/python/path-traversal.md"
title: "Path Traversal — Python"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example

### Flask File Server with os.path.join() Bypass

```python
# 🚫 VULNERABLE — Complete file server
from flask import Flask, send_file
import os

app = Flask(__name__)
BASE_DIR = '/app/data/files'

@app.route('/files')
def list_files():
    # Let's the user list directory
    path = request.args.get('path', '')
    full_path = os.path.join(BASE_DIR, path)
    
    # Attacker can list any directory
    files = os.listdir(full_path)  # 💥
    return {'files': files}

@app.route('/download')
def download_file():
    path = request.args.get('path', '')
    full_path = os.path.join(BASE_DIR, path)
    
    # Even if path exists — attacker can escape with absolute path
    # /download?path=/etc/passwd  →  os.path.join(BASE_DIR, '/etc/passwd')  →  /etc/passwd
    if os.path.exists(full_path):
        return send_file(full_path)  # 💥
    return 'File not found', 404
```

### pathlib.Path Equivalent

```python
# 🚫 VULNERABLE — pathlib path traversal
from pathlib import Path

BASE_DIR = Path('/app/data')

def read_file(filename):
    filepath = BASE_DIR / filename  # 💥 Still traversable
    return filepath.read_text()
# filename = "../../etc/passwd" → /app/data/../../etc/passwd → /etc/passwd
```

### Zip Slip Attack

```python
# 🚫 VULNERABLE — ZIP extraction path traversal
import zipfile

def handle_upload(file):
    with zipfile.ZipFile(file) as zf:
        for entry in zf.infolist():
            # Entry could be: ../../../etc/cron.d/malicious
            zf.extract(entry, '/app/uploads/')  # 💥
```

---