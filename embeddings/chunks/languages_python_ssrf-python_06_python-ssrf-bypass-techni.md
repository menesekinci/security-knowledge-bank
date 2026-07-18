---
source: "languages/python/ssrf-python.md"
title: "Python-Specific SSRF Patterns"
heading: "Python SSRF Bypass Techniques"
category: "language-vuln"
language: "python"
severity: "high"
tags: [aiohttp, cve-2024-35195, cve-2024-37891, cve-2025-53643, language-vuln, overview, python, requests, ssrf, urllib3]
chunk: 6/8
---

## Python SSRF Bypass Techniques

### Technique 1: URL Parsing Differential (CVE-2025-0938)

**Source:** https://www.sentinelone.com/vulnerability-database/cve-2025-0938/

Python's `urllib.parse.urlsplit` and `urlparse` can be tricked because they parse URLs differently from the HTTP libraries that actually make the requests.

```python
# Python's parser vs. HTTP client differential
from urllib.parse import urlsplit

url = "http://evil.com@internal.service/"
parsed = urlsplit(url)
print(parsed.hostname)  # 'evil.com' — looks safe

# But the actual HTTP request might go to 'internal.service'
# depending on how the HTTP library handles the URL
```

### Technique 2: DNS Rebinding

```python
# DNS rebinding bypass
import requests

# First request resolves to safe IP
# DNS record changes
# Second request resolves to internal IP
# No change in URL — bypasses URL validation

def fetch_url_once(url: str):
    """Secure pattern: resolve DNS once and pin the IP."""
    import socket
    from urllib.parse import urlsplit
    
    parsed = urlsplit(url)
    ip = socket.gethostbyname(parsed.hostname)
    
    if not _is_safe_ip(ip):
        raise ValueError(f"Blocked IP: {ip}")
    
    # Use the resolved IP directly, skip DNS
    safe_url = url.replace(parsed.hostname, ip)
    return requests.get(safe_url, headers={"Host": parsed.hostname})
```

### Technique 3: Protocol Smuggling

```python
# Python's urllib accepts many schemes that can be abused
urls = [
    "file:///etc/passwd",           # Read local files
    "gopher://internal:6379/_FLUSHALL",  # Redis command injection
    "dict://internal:6379/INFO",    # Dict protocol to Redis
    "ftp://internal:21/",           # FTP access
]

# Some libraries block these, some don't
# requests: blocks file:// by default (good)
# urllib.request.urlopen: allows file:// (dangerous)
# httpx: allows file:// by default (dangerous)
```

---