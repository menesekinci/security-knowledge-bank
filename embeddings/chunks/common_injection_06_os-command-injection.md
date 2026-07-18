---
source: "common/injection.md"
title: "Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)"
heading: "OS Command Injection"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [command, common-vuln, injection, nosql, vibe, what]
chunk: 6/11
---

## OS Command Injection

### How It Works

User input is passed to system shell commands without sanitization. The attacker injects command separators (`;`, `|`, `&&`, `` ` ``).

### Vulnerable Code Examples

**Python — Vulnerable**
```python
import subprocess, os

filename = request.args.get('file')
# 🔴 VULNERABLE
os.system(f"cat {filename}")         # Shell injection
subprocess.call(f"cat {filename}", shell=True)  # Also vulnerable
```

**Node.js — Vulnerable**
```javascript
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
    const ip = req.query.ip;
    // 🔴 VULNERABLE
    exec(`ping -c 4 ${ip}`, (err, stdout) => {
        res.send(stdout);
    });
});
// Attack: ?ip=8.8.8.8; cat /etc/passwd
```

### Fixed Code Examples

```python
# ✅ SAFE: pass args as a list, never shell=True
import subprocess

filename = request.args.get('file')
# Validate filename is a safe path
if not filename or '/' in filename or '..' in filename:
    abort(400)
subprocess.run(["cat", f"/safe/path/{filename}"], shell=False)

# ✅ SAFE: capture output with subprocess.run + an argument list (never os.popen)
# os.popen() takes a STRING and runs it through the shell — a list is wrong AND unsafe
import subprocess
result = subprocess.run(
    ["ls", "-l", filename], shell=False, capture_output=True, text=True
).stdout
```

```javascript
// ✅ SAFE: use execFile or spawn with argument array
const { execFile } = require('child_process');

app.get('/ping', (req, res) => {
    const ip = req.query.ip;
    // Validate IP address format
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        return res.status(400).send('Invalid IP');
    }
    execFile('ping', ['-c', '4', ip], (err, stdout) => {
        if (err) return res.status(500).send('Ping failed');
        res.send(stdout);
    });
});
```

---