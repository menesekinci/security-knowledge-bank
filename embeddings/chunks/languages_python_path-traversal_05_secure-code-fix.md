---
source: "languages/python/path-traversal.md"
title: "Path Traversal — Python"
heading: "Secure Code Fix"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 5/8
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