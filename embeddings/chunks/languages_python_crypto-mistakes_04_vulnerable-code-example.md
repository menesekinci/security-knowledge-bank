---
source: "languages/python/crypto-mistakes.md"
title: "Crypto Mistakes — Python"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example

### Token Generation with random

```python
# 🚫 VULNERABLE — Complete reset password flow
import random
import string
from flask import Flask, request

app = Flask(__name__)

@app.route('/reset-password')
def reset_password():
    user_id = request.args.get('uid')
    
    # AI generates reset token with random (PREDICTABLE!)
    chars = string.ascii_letters + string.digits
    token = ''.join(random.choices(chars, k=32))  # 💥 Mersenne Twister!
    
    store_token(user_id, token)
    send_email(f"Click here to reset: https://example.com/reset?token={token}")
    return "Check your email"

# Attackers who obtain one token can predict future tokens
# by recovering the PRNG state from observed tokens!
```

### Custom Encryption Implementation

```python
# 🚫 VULNERABLE — AI-generated secure messaging
def encrypt_message(message, password):
    """'Secure' encryption — actually just XOR."""
    # AI thinks this is secure encryption
    key = hashlib.md5(password.encode()).digest()  # 💥 MD5
    result = bytearray()
    for i, b in enumerate(message.encode()):
        result.append(b ^ key[i % len(key)])  # 💥 XOR
    return bytes(result)

# Both MD5 and XOR are trivial to break.
```

### Fernet with Wrong Key Encoding

```python
# 🚫 VULNERABLE — AI-generated Fernet misuse
from cryptography.fernet import Fernet
import base64

# AI tries to use a raw string as a Fernet key
f = Fernet("my-secret-key")  # 💥 TypeError or wrong encoding
# Correct: Fernet expects 32 url-safe base64-encoded bytes
```

---