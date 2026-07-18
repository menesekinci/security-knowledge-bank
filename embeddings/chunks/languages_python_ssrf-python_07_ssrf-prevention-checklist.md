---
source: "languages/python/ssrf-python.md"
title: "Python-Specific SSRF Patterns"
heading: "SSRF Prevention Checklist for Python"
category: "language-vuln"
language: "python"
severity: "high"
tags: [aiohttp, cve-2024-35195, cve-2024-37891, cve-2025-53643, language-vuln, overview, python, requests, ssrf, urllib3]
chunk: 7/8
---

## SSRF Prevention Checklist for Python

### Library-Specific Protections

| Library | Risk | Protection |
|---------|------|------------|
| `requests` | Redirect following | `allow_redirects=False` + manual validation |
| `httpx` | Follows redirects | `follow_redirects=False` |
| `aiohttp` | Follows redirects | `max_redirects=0` |
| `urllib` | Many schemes allowed | Use `requests` instead, or filter schemes |
| `urllib3` | Proxy SSRF | Upgrade to >= 2.2.2 |

### Universal Defenses

```python
import re
from urllib.parse import urlparse

BLOCKED_HOSTS = re.compile(
    r'(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|10\.|172\.1[6-9]\.|'
    r'172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|169\.254\.)'
)

BLOCKED_SCHEMES = {'file', 'gopher', 'dict', 'ftp', 'ldap', 'tftp'}

ALLOWED_SCHEMES = {'http', 'https'}

def validate_outbound_url(url: str) -> bool:
    """Comprehensive SSRF validation for any Python HTTP library."""
    parsed = urlparse(url)
    
    # 1. Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    
    # 2. Check hostname
    if BLOCKED_HOSTS.match(parsed.hostname or ''):
        return False
    
    # 3. Resolve and double-check IP
    try:
        import socket
        ip = socket.gethostbyname(parsed.hostname)
        if BLOCKED_HOSTS.match(ip):
            return False
    except socket.gaierror:
        return False
    
    # 4. Check for DNS rebinding: verify resolution again before request
    return True
```

---