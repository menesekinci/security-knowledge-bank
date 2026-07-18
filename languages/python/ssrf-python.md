# Python-Specific SSRF Patterns

> **Category:** Server-Side Request Forgery  
> **Language:** Python  
> **Severity:** High to Critical  
> **CVEs covered:** CVE-2024-35195 (requests), CVE-2024-37891 (urllib3 Proxy-Authorization leak), CVE-2025-53643 (aiohttp)

## Overview

Server-Side Request Forgery (SSRF) in Python manifests uniquely due to the standard library's URL parsing behavior, redirect handling, and the ecosystem's HTTP libraries (`requests`, `httpx`, `aiohttp`). Python's `urllib` has historically been permissive about URL schemes and redirect following, creating SSRF vectors that differ from other languages.

---

## CVE-2024-35195: requests Library Session Certificate Bypass

**CVSS:** 5.6 (Medium)  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-35195 • GHSA-9wx4-h78v-vm56

### Description

The `requests` library before 2.32.0 had a critical flaw in its `Session` object: when the *first* request to a host used `verify=False` (disabling TLS certificate verification), **all subsequent requests to that same host** would also ignore certificate verification — even if the code explicitly set `verify=True` on later requests.

### Root Cause

The `requests` library uses connection pooling via `urllib3`. Once a connection was established with `verify=False`, the connection pool cached that configuration for the host's lifetime. Changing the `verify` parameter on subsequent requests had **no effect** — the cached insecure connection was reused.

### Vulnerable Code

```python
import requests

session = requests.Session()

# First request: disable verification (e.g., for a staging endpoint)
session.get("https://internal.api.service/data", verify=False)

# Second request: attempt to re-enable verification — DOES NOT WORK!
# The connection pool still uses the insecure connection
response = session.get("https://internal.api.service/admin", verify=True)
# This request still ignores certificate errors!
```

### Exploit Scenario

1. An application has a `Session` shared across code paths
2. One code path disables verification for a legitimate reason (e.g., self-signed cert, debugging)
3. An attacker triggers a request to the same host via a different code path that expects verification
4. The attacker can now intercept the supposedly verified connection with a MitM attack

### Fixed Code

```python
import requests

# Option 1: Use separate sessions for different verification levels
session_verified = requests.Session()
session_unverified = requests.Session()

session_unverified.get("https://internal.api.service/data", verify=False)
session_verified.get("https://internal.api.service/admin", verify=True)
# These sessions do not share connection pools

# Option 2: Upgrade to requests >= 2.32.0
# The fix clears the connection pool when verify parameter changes

# Option 3: Use close() to clear pool
session = requests.Session()
session.get("https://internal.api.service/data", verify=False)
session.close()  # Clear the pool
session.get("https://internal.api.service/admin", verify=True)  # Now works correctly
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-35195
- https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56
- https://github.com/psf/requests/commit/a58d7f2ffb4d00b46dca2d70a3932a0b37e22fac

---

## CVE-2024-37891: urllib3 Proxy-Authorization Leak on Cross-Origin Redirect

**CVSS:** 6.5 (Medium)  
**Fixed in:** urllib3 1.26.19 and 2.2.2  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-37891

### Description

`urllib3` before 1.26.19 / before 2.2.2 (>= 2.0.0) did **not** treat a manually-set `Proxy-Authorization` HTTP header as authentication material, so it was **not stripped on cross-origin redirects**. If an application set that header itself (on a `PoolManager`/`Session` rather than via urllib3's proxy support) and the server responded with a redirect to another origin, urllib3 forwarded the proxy credentials to the redirect target.

This is a **credential leak**, not the proxy-controlled-redirect SSRF it is sometimes described as — but a leaked proxy credential lets an attacker who controls (or can influence a redirect to) an external host recover credentials that reach internal proxies, which feeds SSRF/lateral-movement chains.

### Vulnerable Code Pattern

```python
import urllib3

# App sets Proxy-Authorization itself, NOT through urllib3's proxy support
http = urllib3.PoolManager(headers={"Proxy-Authorization": "Basic c2VjcmV0"})

# api.example.com returns 302 -> https://attacker.example/
# On vulnerable urllib3 the Proxy-Authorization header is re-sent to attacker.example
response = http.request("GET", "https://api.example.com/data")
# Attacker now has the proxy credential
```

### Exploit

1. Application attaches a `Proxy-Authorization` header to a client/session
2. A requested host issues a cross-origin redirect (attacker-controlled or attacker-influenced)
3. Vulnerable urllib3 replays the `Proxy-Authorization` header to the new origin
4. The proxy credential is disclosed to a host that should never see it

### Fixed Code

```python
# Option 1: Upgrade to urllib3 >= 1.26.19 or >= 2.2.2
# The fix strips Proxy-Authorization on cross-origin redirects.

# Option 2: Never set Proxy-Authorization as a default header.
# Use urllib3's proxy support so the header only goes to the proxy:
import urllib3

proxy = urllib3.ProxyManager(
    "http://proxy.internal:8080",
    proxy_headers=urllib3.make_headers(proxy_basic_auth="user:pass"),
)
resp = proxy.request("GET", "https://api.example.com/data")

# Option 3: Disable redirects and validate each hop yourself
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def safe_request(url: str):
    parsed = urllib3.util.parse_url(url)
    if parsed.host not in ALLOWED_HOSTS:
        raise ValueError(f"Host {parsed.host} not in allowlist")

    http = urllib3.PoolManager()
    response = http.request("GET", url, redirect=False)
    if response.status in (301, 302, 307, 308):
        redirect_url = response.headers.get("Location", "")
        redirect_parsed = urllib3.util.parse_url(redirect_url)
        if redirect_parsed.host not in ALLOWED_HOSTS:
            raise ValueError(f"Redirect to {redirect_parsed.host} blocked")
        return http.request("GET", redirect_url)
    return response
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2024-37891
- https://github.com/urllib3/urllib3/security/advisories/GHSA-34jh-p97f-mpxf

---

## CVE-2025-53643: aiohttp Request Smuggling / SSRF

**CVSS:** 7.5 (High)  
**Fixed in:** aiohttp 3.12.14  
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-53643

### Description

CVE-2025-53643 is a request smuggling vulnerability in `aiohttp` (the async HTTP client/server for Python) before **3.12.14**: the **pure-Python** HTTP parser does not parse the trailer section of a chunked request (it only affects installs without the C extensions, or with `AIOHTTP_NO_EXTENSIONS` set). An attacker can smuggle a request past a front-end proxy/firewall, which can be chained with SSRF to reach internal services.

### Related CVEs in the Chain

| CVE | CVSS | Issue | Impact |
|-----|------|-------|--------|
| CVE-2025-53643 | 7.5 | Request smuggling — trailer section not parsed (pure-Python parser, < 3.12.14) | Proxy/firewall bypass → SSRF chain |
| CVE-2025-69224 | 6.5 | Request smuggling via non-ASCII characters (pure-Python parser, ≤ 3.13.2) | Proxy/firewall bypass → SSRF chain |
| CVE-2025-69226 | 5.3 | Static-file path normalization reveals whether absolute paths exist (≤ 3.13.2) | Information disclosure |
| CVE-2026-22815 | 7.5 | Uncapped memory in header/trailer handling (< 3.13.4) | DoS (memory exhaustion) — **not** SSRF |

### Vulnerable Code

```python
# VULNERABLE: aiohttp < 3.12.14 (multiple CVE chain)
from aiohttp import web

async def handle(request):
    # The HTTP parser does not properly handle trailer sections
    # An attacker can smuggle requests disguised as trailers
    data = await request.post()  # Can be tricked
    # Process data...
    return web.Response(text="OK")

app = web.Application()
app.router.add_post("/process", handle)
```

### SSRF Chaining with aiohttp Client

```python
# VULNERABLE: aiohttp client following redirects to internal hosts
import aiohttp

async def fetch_user_data(user_id: int):
    async with aiohttp.ClientSession() as session:
        # If external service responds with redirect to internal
        async with session.get(f"https://api.external.com/users/{user_id}") as resp:
            # aiohttp follows redirects by default
            # Could end up at http://localhost:6379/ (Redis) etc.
            return await resp.json()
```

### Secure Code

```python
# Upgrade to aiohttp >= 3.12.14 (and >= 3.13.4 for CVE-2026-22815)
from aiohttp import web, ClientSession, ClientTimeout
from urllib.parse import urlparse

# Also restrict redirect following
async def fetch_user_data_safe(user_id: int):
    timeout = ClientTimeout(total=10)
    async with ClientSession() as session:
        async with session.get(
            f"https://api.external.com/users/{user_id}",
            timeout=timeout,
            max_redirects=0  # Don't follow redirects automatically
        ) as resp:
            if resp.status in (301, 302, 307, 308):
                # Manually validate redirect target
                location = resp.headers.get("Location", "")
                if not _is_safe_url(location):
                    raise ValueError("Redirect blocked: SSRF prevention")
                async with session.get(location, max_redirects=5) as redirect_resp:
                    return await redirect_resp.json()
            return await resp.json()

def _is_safe_url(url: str) -> bool:
    """Check that URL doesn't point to internal resources."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    # Block private/reserved IPs
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "[::1]"):
        return False
    if host.startswith("169.254.") or host.startswith("10."):
        return False
    if host.startswith("192.168.") or host.startswith("172.16."):
        return False
    return True
```

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2025-53643
- https://linuxsecurity.com/advisories/deblts/debian-dla-4613-1-python-aiohttp
- https://github.com/aio-libs/aiohttp/security/advisories/GHSA-45c4-8wx5-qw6w

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

## References

1. https://nvd.nist.gov/vuln/detail/CVE-2024-35195 — requests session cert bypass
2. https://nvd.nist.gov/vuln/detail/CVE-2024-37891 — urllib3 proxy SSRF
3. https://nvd.nist.gov/vuln/detail/CVE-2025-53643 — aiohttp request smuggling
4. https://www.sentinelone.com/vulnerability-database/cve-2025-0938/ — Python URL parser differential
5. https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56 — requests advisory
6. https://github.com/aio-libs/aiohttp/security/advisories/GHSA-45c4-8wx5-qw6w — aiohttp advisory
7. https://github.com/Kozea/WeasyPrint/security/advisories/GHSA-983w-rhvv-gwmv — WeasyPrint SSRF via urllib
