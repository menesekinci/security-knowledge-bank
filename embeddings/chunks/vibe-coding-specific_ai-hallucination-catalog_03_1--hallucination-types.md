---
source: "vibe-coding-specific/ai-hallucination-catalog.md"
title: "🔴 AI Hallucination Catalog — Security Context"
heading: "1. Hallucination Types"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [hallucination, real, references, table, types, vibe-coding, world]
chunk: 3/6
---

## 1. Hallucination Types

### Type 1: Fabricated CVE

AI generates non-existent CVE numbers. This is one of the most dangerous types of hallucination because:

- The developer thinks "There's a CVE, so it's a valid security issue"
- The CVE number looks real (`CVE-2024-XXXXX`)
- Fake CVEs affect real security assessments

**Examples:**

```text
AI: "This library has CVE-2024-99999 which allows remote code execution"
→ In reality, there is no record called CVE-2024-99999!
→ The AI has just memorized the pattern "CVE-" + reasonable year + 5 digits.

AI: "CVE-2023-51234 affects Django REST Framework versions < 3.14"
→ There is no record called CVE-2023-51234!
→ The AI produced it using patterns seen from similar CVEs.
```

**📊 Data:** In one study, **30-40%** of CVE references produced by AI could not be found in reality (Source: Aqua Security, 2024).

### Type 2: Outdated / Post-Cutoff API

AI models' training data is cut off at a certain date (knowledge cutoff). They cannot know API versions, framework changes, and security updates released **after** this date.

**Risk Matrix:**

| Area | Risk Level | Description |
|------|------------|-------------|
| **Django/Flask/FastAPI** | 🔴 High | Old route definitions (`url()` → `path()`) |
| **React/Next.js** | 🔴 High | Old hook/API usage (App Router vs Pages Router) |
| **Python 3.12+** | 🟡 Medium | New syntax features, old patterns |
| **Kubernetes** | 🔴 High | Old API versions (v1beta1 → v1) |
| **JWT libraries** | 🟡 Medium | Old `decode()` API parameters |
| **TensorFlow/PyTorch** | 🟡 Medium | Old layer/function names |
| **Cryptography libraries** | 🔴 Critical | Old / deprecated algorithms |

**Example:**

```python
# AI-written "Django 5.2" code (cutoff: 2024):
from django.conf.urls import url  # ❌ NOT in Django 4.0+!

# Correct way in 2026:
from django.urls import path
urlpatterns = [
    path('login/', login_view),
]
```

### Type 3: Fake Security (Pseudo-Security)

AI produces code that looks like a security measure but is actually **useless**. The developer relaxes thinking "I've added security," when in fact the code is still vulnerable.

**Most Common Patterns:**

| # | Pattern | AI's Output | Real Solution |
|---|---------|-------------|---------------|
| 1 | **Own Encryption** | XOR cipher, base64 "encryption" | `cryptography` / `PyNaCl` |
| 2 | **JWT alg:none** | `jwt.decode(token, options={"verify_signature": False})` | Signature verification required |
| 3 | **Manual SQL Sanitization** | `username.replace("'", "\\'")` | Parametrized query |
| 4 | **Incomplete HTML Escape** | Only escaping `<` and `>` | DOMPurify / comprehensive escape |
| 5 | **Wrong Hash** | `hashlib.sha1(password)` | `bcrypt` / `argon2` |
| 6 | **Base64 "Encryption"** | `base64.b64encode(data)` | AES-256-GCM / libsodium |
| 7 | **Wrong CSP** | `Content-Security-Policy: *` | Specific policy |

**Example:**

```python
# AI-written "secure" XOR encryption:
def encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
# ❌ This is not encryption, it's obfuscation. Cryptographically useless.
```

### Type 4: Non-Existent Library

AI suggests libraries that either never existed or don't exist under the name the AI suggests. This is a golden opportunity for **supply chain attacks**: an attacker can publish the name the AI hallucinated on PyPI/npm.

**Examples:**

```text
AI: "Use pip install pypdf-extractor"
     → There is NO popular package called pypdf-extractor!

AI: "Use the safe-cryptography library"
     → There is NO PyPI package called safe-cryptography!

AI: "npm install jwt-validator"
     → jwt-validator is a real package on npm but doesn't have the API the AI described!
```

**📊 Data:**
- **Lemniscap Research (2023):** **20%** of npm packages recommended by AI do not actually exist.
- **Aqua Security (2022):** Demonstrated that GitHub Copilot suggests non-existent libraries that could be purchased.
- **PyPI Hallucination Squatting (2023):** A researcher proved 40,000+ downloads by purchasing PyPI package names that ChatGPT hallucinated.

### Type 5: Obsolete Best Practice — Outdated Recommendation

AI recommends security practices that it has seen in its training data but are no longer valid.

**Dangerous Examples:**

| Old Practice | AI Suggestion | Current Correct |
|--------------|---------------|-----------------|
| **MD5 Hashing** | `hashlib.md5(data)` | SHA-256 or SHA-3 |
| **SHA-1 Hashing** | `hashlib.sha1(data)` | SHA-256 or SHA-3 |
| **ECB Mode** | `AES.new(key, AES.MODE_ECB)` | AES-GCM or ChaCha20-Poly1305 |
| **SSL (deprecated)** | `ssl.wrap_socket()` | TLS 1.2+ context |
| **bcrypt cost=4** | `bcrypt.gensalt(4)` | `bcrypt.gensalt(12)` |
| **HTTP (no TLS)** | `http://api.example.com` | `https://` |
| **CSP unsafe-inline** | `'unsafe-inline'` | Nonce or hash-based CSP |

**Example:**

```python
# AI-written in 2026:
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()  # ❌ MD5 — broken in 2004!
# Correct way:
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

### Type 6: Test Blindness — Untested Code Assurance

AI **assumes the code it produced has been tested** but doesn't write tests, or writes insufficient tests. The developer skips security tests thinking "AI wrote the tests too."

**Common Patterns:**

```python
# AI-written "test":
def test_encrypt():
    result = encrypt("hello", "key")
    assert result is not None  # ❌ This test verifies NOTHING!
    assert len(result) > 0      # ❌ Meaningless assertion

# Tests the AI SKIPPED:
# - Does Decrypt(encrypt(x)) == x?
# - Different keys produce different results?
# - What happens with empty input?
# - Buffer overflow test?
```

### Type 7: Wrong Implementation — Correct Concept, Wrong Code

AI knows the correct security concept but implements it incorrectly. This is the most insidious type of hallucination because:

- The code compiles/runs
- The overall structure looks correct
- But there is a security vulnerability

**Examples:**

```python
# AI-written JWT verification — knows the framework but misremembers the API
import jwt

# AI-written:
payload = jwt.decode(token, key, algorithms=['HS256'])
# ❌ This is the old PyJWT API. In the new version:
# payload = jwt.decode(token, key, algorithms=['HS256'])
#   → Actually correct but the 'algorithms' parameter is old.
#   → In newer PyJWT: payload = jwt.decode(token, key, algorithms=['HS256']) still works
#   → But if AI writes verify=False: jwt.decode(token, options={"verify_signature": False})
```

---