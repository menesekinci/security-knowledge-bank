---
source: "languages/python/case-studies/python-path-traversal.md"
title: "Python Path Traversal Vulnerability (CVE-2024-46987) — Python/Web"
category: "case-study"
language: "python"
severity: "critical"
tags: [case-study, cause, happened, impact, python, root, system, target, what, when]
---

# Python Path Traversal Vulnerability (CVE-2024-46987) — Python/Web

## 📅 When Did It Happen?
2024 (CVE-2024-46987)
Similar vulnerabilities: discovered regularly (CVE-2024-53844, CVE-2024-38819 and more)

## 🎯 Target System
Python web applications (Flask, Django, FastAPI) — file serving, download, or upload endpoints.

## 🔴 What Happened?
CVE-2024-46987 is a common **Path Traversal (CWE-22)** security vulnerability. This flaw occurs because the application fails to properly validate user-supplied file paths.

**How it works:**
```python
# Vulnerable example
@app.route('/download')
def download():
    filename = request.args.get('file')
    # If user sends ../../etc/passwd...
    return send_file(f'/var/app/files/{filename}')
```

An attacker can access any file on the application's file system using a path like `../../../etc/passwd`.

**Real-world cases (2024):**
- **CVE-2024-46987**: Path traversal in a web application — user input was used directly as a file path
- **CVE-2024-53844 (EDDI)**: Path traversal in a Python application (versions 4.3-5.3)
- **CVE-2024-38819 (Spring Framework)**: Path traversal in Java (same pattern exists in Python)

These vulnerabilities are discovered regularly because developers forget to validate user input when using it in file operations.

## 🧠 Root Cause
1. **Direct use of user input as a file path** — the most fundamental mistake
2. **`../` characters not filtered** — directly leads to path traversal
3. **Insufficient input validation** — file name is not sanitized, only file existence is checked
4. **No chroot/jail used** — application has full access to the file system

## 💥 Impact
- **Access to sensitive files**: `/etc/passwd`, SSL private keys, `.env` files, database backups
- **Source code leakage**: `.py`, `.js` files can be read
- **Credential leakage**: environment variable files, configuration files
- **Further attacks**: LFI (Local File Inclusion) -> can escalate to RCE
- Log files -> session token/credential theft

## 🔧 How Was It Fixed?
- Input validation added: `os.path.basename()` or `os.path.abspath()` + `startswith()` check
- Allowlist-based validation: only allow access to files in permitted directories
- Chroot or Docker for isolated file system
- Use of secure libraries: `send_from_directory()` (Flask) and similar

## 🎓 Lessons Learned
1. **Never use user input directly as a file path**
2. **Calculate the absolute path with `os.path.abspath()` and verify it starts with the expected directory**
3. **Use `os.path.basename()`** — extracts only the file name, discards the path
4. **Use the framework's safe functions**: Flask's `send_from_directory()`, Django's `FileResponse`
5. **Chroot/Docker isolation** — limit the damage even if a path traversal succeeds

## Vibe Coding Connection: How this error can be reproduced in AI code generation
When AI is asked to "create a file download endpoint", it almost always generates code that uses user input directly as a file path:
```python
# Pattern AI frequently generates
@app.route('/files/<path:filename>')
def get_file(filename):
    return send_file(f'/data/{filename}')  # VULNERABLE TO PATH TRAVERSAL!
```
Even though AI has seen code patterns that prevent path traversal (basename, abspath check) in its training data, it prefers using direct paths as the "simple solution". When generating file handling code with AI, explicitly specify to add path traversal protection.

## 🔗 Source / Reference (URL)
- https://www.aikido.dev/blog/path-traversal-in-2024-the-year-unpacked
- https://xbow.com/blog/xbow-eddi-path
- https://www.yeswehack.com/learn-bug-bounty/practical-guide-path-traversal-attacks
