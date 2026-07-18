---
source: "languages/python/path-traversal.md"
title: "Path Traversal — Python"
heading: "Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 6/8
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