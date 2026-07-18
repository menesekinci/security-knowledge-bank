---
source: "languages/python/timing-attacks.md"
title: "Timing Attack Vectors in Python"
heading: "General Vulnerable Patterns in Python"
category: "language-vuln"
language: "python"
severity: "medium"
tags: [cve-2020-25659, cve-2023-50782, cve-2024-23342, general, language-vuln, overview, python, python-cryptography, python-ecdsa, vulnerable]
chunk: 6/8
---

## General Vulnerable Patterns in Python

### Pattern 1: String Comparison with `==`

```python
# VULNERABLE: Short-circuit string comparison
def verify_token(user_token, expected):
    return user_token == expected
    # Returns False on first differing character — TIMING LEAK

# SECURE: Constant-time comparison
import hmac
def verify_token_secure(user_token, expected):
    if len(user_token) != len(expected):
        return False  # Still leaks length — ensure equal lengths
    return hmac.compare_digest(user_token, expected)
```

### Pattern 2: Password Verification

```python
# VULNERABLE
import bcrypt

def check_password_vulnerable(stored_hash, provided_password):
    # bcrypt is constant-time internally, but early return on format check leaks info
    if not stored_hash or len(stored_hash) != 60:
        return False  # Timing leak: valid hashes are 60 chars
    return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())

# SECURE
def check_password_secure(stored_hash, provided_password):
    # Always process regardless of perceived validity
    try:
        return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())
    except ValueError:
        # Invalid hash format — still take similar time
        bcrypt.checkpw(b"dummy", b"$2b$12$" + b"x" * 53)  # Pad timing
        return False
```

### Pattern 3: JWT/HMAC Verification

```python
# VULNERABLE: Custom HMAC comparison
import hashlib
import hmac

def verify_hmac_vulnerable(secret, message, signature):
    expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return expected == signature  # Timing leak via ==

# SECURE: Use compare_digest
def verify_hmac_secure(secret, message, signature):
    expected = hmac.new(secret, message, hashlib.sha256).digest()
    return hmac.compare_digest(expected, bytes.fromhex(signature))
```

---