# Path Traversal

**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
**OWASP Top 10:2021:** A01 — Broken Access Control
**CWE Top 25 2024:** #5 (Path Traversal — up from #8, rising trend)

---

## What Is Path Traversal?

Path traversal (directory traversal) allows an attacker to read or write files **outside the intended directory** by manipulating file paths with `../` sequences or absolute paths. Attackers can read system files (`/etc/passwd`, `config.php`), source code, or overwrite critical files.

## Why Vibe Coding Makes This Worse

- **AI builds file-serving endpoints:** "Create endpoint to serve user avatars" → concatenates filename into path
- **AI doesn't sanitize `../`:** Generated code trusts user-supplied filenames
- **AI generates dynamic require/import:** `require(`./modules/${userInput}`)` — path traversal into module loading
- **ZIP extraction without checks:** AI writes file unzipping code but forgets to validate extracted paths

## Vulnerable Code Examples

**Python — Vulnerable**
```python
from flask import Flask, send_file, request

@app.route('/files/<filename>')
def get_file(filename):
    # 🔴 VULNERABLE: no path sanitization
    return send_file(f'/var/app/files/{filename}')
# Attack: /files/../../../etc/passwd → reads /etc/passwd
```

**Node.js — Vulnerable**
```javascript
const express = require('express');
const path = require('path');

app.get('/download/:filename', (req, res) => {
    const filePath = path.join('/var/app/data', req.params.filename);
    // 🔴 VULNERABLE: path.join alone doesn't prevent traversal
    // path.join('/var/app/data', '../../../etc/passwd') → '/etc/passwd'
    res.sendFile(filePath);
});
```

**PHP — Vulnerable**
```php
$file = $_GET['file'];
// 🔴 VULNERABLE
include("includes/" . $file);
// Attack: ?file=../../../etc/passwd%00  (null byte injection on old PHP)
```

## Fixed Code Examples

**Python — Fixed**
```python
import os
from flask import abort, send_file

UPLOAD_DIR = '/var/app/files'

@app.route('/files/<filename>')
def get_file(filename):
    # ✅ Resolve the full path
    full_path = os.path.normpath(os.path.join(UPLOAD_DIR, filename))
    # ✅ Verify it's within the allowed directory
    if not full_path.startswith(os.path.normpath(UPLOAD_DIR)):
        abort(403)
    # ✅ Verify the file exists
    if not os.path.isfile(full_path):
        abort(404)
    return send_file(full_path)
```

**Node.js — Fixed**
```javascript
const express = require('express');
const path = require('path');

const ALLOWED_DIR = path.resolve('/var/app/data');

app.get('/download/:filename', (req, res) => {
    // ✅ Resolve against allowed directory
    const requestedPath = path.resolve(ALLOWED_DIR, req.params.filename);

    // ✅ Verify resolved path is within allowed directory
    if (!requestedPath.startsWith(ALLOWED_DIR)) {
        return res.status(403).send('Forbidden');
    }

    // ✅ Check file exists
    if (!fs.existsSync(requestedPath)) {
        return res.status(404).send('Not found');
    }

    res.sendFile(requestedPath);
});
```

**PHP — Fixed**
```php
$baseDir = '/var/app/files/';
$file = basename($_GET['file']);  // Strips path components
$fullPath = $baseDir . $file;

if (!file_exists($fullPath)) {
    die('File not found');
}

// Verify within base dir
$realBase = realpath($baseDir);
$realPath = realpath($fullPath);
if (strpos($realPath, $realBase) !== 0) {
    die('Access denied');
}

readfile($fullPath);
```

## ZIP Slip Attack

A common path traversal via malicious ZIP archives:

```python
import zipfile

# 🔴 VULNERABLE: ZIP extraction without path checking
with zipfile.ZipFile('upload.zip') as zf:
    zf.extractall('/app/extracted')
    # A malicious ZIP contains: ../../etc/cronjob  → overwrites cron!
```

**Fixed:**
```python
import zipfile
import os

EXTRACT_DIR = '/app/extracted'

with zipfile.ZipFile('upload.zip') as zf:
    for member in zf.namelist():
        # ✅ Resolve and check path
        member_path = os.path.realpath(os.path.join(EXTRACT_DIR, member))
        if not member_path.startswith(os.path.realpath(EXTRACT_DIR)):
            raise Exception('Path traversal in ZIP file')
        zf.extract(member, EXTRACT_DIR)
```

---

## Prevention Checklist for AI Prompts

```
✅ PATH TRAVERSAL PREVENTION:
- Never build file paths from user input without validation
- Normalize and resolve paths (realpath, path.resolve) before access
- Verify resolved path is within the intended base directory
- Use basename() to strip directory components from filenames
- Reject filenames containing ../, ..\, or null bytes
- Use a mapping layer (e.g., file ID → actual path) instead of raw paths
- Validate file type by content, not extension
- Set read-only permissions on served directories
- When extracting archives, check each file's resolved path
```

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Apache HTTP Server path traversal | CVE-2021-41773 | Arbitrary file disclosure / RCE (2.4.49, exploited in the wild) |
| aiohttp static-route path traversal | CVE-2024-23334 | Arbitrary file read via `../` when `follow_symlinks=True` |
| Argo CD Helm path traversal | CVE-2022-24348 | Read files outside the repo → secret disclosure |
| Citrix ADC path traversal | CVE-2019-19781 | RCE in VPN gateways |
| Zimbra path traversal | CVE-2022-27925 | RCE via file upload bypass |

---

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)
- [PortSwigger Path Traversal Guide](https://portswigger.net/web-security/file-path-traversal)
