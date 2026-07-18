# Path Traversal — Python

> **Severity:** High
> **CVSS:** 7.5 (High)
> **AI Generation Risk:** High — AI models frequently concatenate user input to file paths

---

## Vulnerability Explanation

Path traversal (also known as directory traversal) occurs when user-controlled input is used to construct file paths without proper validation. An attacker can use `../` sequences or absolute paths to escape the intended directory and read/write arbitrary files on the system.

### The Core Problem

```python
# User input: ../../../etc/passwd
# Intended:   /app/uploads/../../../etc/passwd
# Resolved:   /etc/passwd
```

Python functions like `open()`, `os.path.join()`, `Path.open()`, and `pathlib.Path` all resolve `..` and symlinks, making them vulnerable if input isn't validated.

### Common File Access Functions

| Function | Traversal Risk | Symlink Risk |
|---|---|---|
| `open(path, ...)` | ✅ | ✅ |
| `pathlib.Path(path).read_text()` | ✅ | ✅ |
| `os.path.join(base, user_input)` | ⚠️ Can still be escaped with absolute paths | ✅ |
| `os.path.abspath()` | ✅ (just resolves) | ✅ |
| `os.path.realpath()` | ✅ (resolves symlinks) | ✅ (feature) |

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

## Secure Code Fix

### Fix 1: Resolve and Validate Path

```python
# ✅ SAFE — Resolve to canonical path and validate
import os

BASE_DIR = os.path.abspath('/app/data/files')

def safe_send_file(filename):
    # Join and resolve to canonical path
    full_path = os.path.realpath(os.path.join(BASE_DIR, filename))
    
    # Ensure the resolved path starts with BASE_DIR
    if not full_path.startswith(BASE_DIR):
        raise PermissionError("Access denied")
    
    # Ensure the file exists and is actually a file
    if not os.path.isfile(full_path):
        raise FileNotFoundError("File not found")
    
    return send_file(full_path)
```

### Fix 2: Use pathlib for Cleaner Validation

```python
# ✅ SAFE — pathlib with validation
from pathlib import Path

BASE_DIR = Path('/app/data').resolve()

def safe_read_file(filename):
    # Resolve the full path
    filepath = (BASE_DIR / filename).resolve()
    
    # Verify it's within BASE_DIR
    if BASE_DIR not in filepath.parents and filepath != BASE_DIR:
        raise PermissionError("Access denied")
    
    return filepath.read_text()
```

### Fix 3: Whitelist Allowed Files

```python
# ✅ SAFE — Whitelist approach (most restrictive)
ALLOWED_FILES = {
    'report-2024.pdf',
    'summary-q4.pdf',
    'readme.txt',
}

def download_file(filename):
    if filename not in ALLOWED_FILES:
        raise PermissionError("File not available")
    
    filepath = os.path.join('/app/data/files/', filename)
    return send_file(filepath)
```

### Fix 4: Generate UUID-Based Filenames

```python
# ✅ SAFE — Don't use user-provided filenames at all
import uuid
import os

UPLOAD_DIR = '/app/uploads/'

def store_file(uploaded_file):
    # Generate a random UUID filename
    extension = os.path.splitext(uploaded_file.filename)[1]
    safe_filename = str(uuid.uuid4()) + extension
    save_path = os.path.join(UPLOAD_DIR, safe_filename)
    
    # Verify path is still within UPLOAD_DIR (defense in depth)
    save_path = os.path.realpath(save_path)
    if not save_path.startswith(os.path.realpath(UPLOAD_DIR)):
        raise PermissionError("Access denied")
    
    uploaded_file.save(save_path)
    return safe_filename
```

### Fix 5: Safe Archive Extraction

```python
# ✅ SAFE — Validate extraction paths
import zipfile
import os

def safe_extract(zip_path, extract_dir):
    extract_dir = os.path.realpath(extract_dir)
    
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for entry in zf.infolist():
            # Resolve the full extraction path
            entry_path = os.path.realpath(os.path.join(extract_dir, entry.filename))
            
            # Validate it's within the extract directory
            if not entry_path.startswith(extract_dir):
                raise PermissionError(f"Zip slip detected: {entry.filename}")
            
            zf.extract(entry, extract_dir)
```

---

## Prevention Checklist

- [ ] NEVER concatenate user input directly into file paths
- [ ] ALWAYS resolve paths to canonical form (`os.path.realpath()`)
- [ ] ALWAYS verify the resolved path starts with the intended base directory
- [ ] For file downloads, prefer a whitelist-based approach
- [ ] Store user-uploaded files with UUID names, not user-provided names
- [ ] Validate archive extraction paths before extracting
- [ ] Use `os.path.commonpath()` for path containment checks
- [ ] Set filesystem permissions to limit what the app can read
- [ ] Run the application in a container with read-only root filesystem
- [ ] Use `send_from_directory()` in Flask (built-in path validation)

---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2007-4559** | Python `tarfile` — `extract()`/`extractall()` follow `..` sequences in TAR member names ("tarbomb") | Arbitrary file overwrite → potential RCE |
| **CVE-2024-23334** | aiohttp 1.0.5–3.9.1 — `web.static(..., follow_symlinks=True)` fails to canonicalize paths, allowing `../` traversal | Arbitrary file read |
| **CVE-2023-41105** | CPython 3.11–3.11.4 — `os.path.normpath()` truncates the path at an embedded `\0` byte, bypassing allowlist checks | Path-allowlist bypass |
| **CVE-2021-33203** | Django <2.2.24 / <3.1.12 / <3.2.4 — `admindocs` `TemplateDetailView` directory traversal outside template roots | Arbitrary file existence/content disclosure |
| **CVE-2019-14322** | Werkzeug <0.15.5 — `SharedDataMiddleware` mishandles Windows drive letters (e.g. `C:`) via `os.path.join()` | Arbitrary file read (Windows) |

---

## Vibe Coding Red Flags

In AI-generated Python, flag these immediately:

```python
open(request.args.get('path'))                    # 💥 Direct user-controlled
open(f'/dir/{user_input}')                        # 💥 Concatenation
os.path.join('/dir/', user_input)                 # ⚠️ Bypassable with absolute path
Path('/dir/') / user_input                        # ⚠️ Same bypass
send_file(os.path.join('/dir/', user_input))      # ⚠️ Traversal risk
zipfile.extractall('/dir/')                       # ⚠️ Zip slip without validation
```

> **Golden Rule:** `os.path.join()` is NOT a security function. It's a string concatenation utility. Always call `os.path.realpath()` and check the prefix.
