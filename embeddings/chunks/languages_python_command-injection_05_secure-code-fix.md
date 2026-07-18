---
source: "languages/python/command-injection.md"
title: "Command Injection — Python"
heading: "Secure Code Fix"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 5/8
---

## Secure Code Fix

### Fix 1: Use subprocess Without shell=True (Best Practice)

```python
# ✅ SAFE — subprocess with list arguments, no shell
import subprocess

def ping_host(host):
    result = subprocess.run(
        ["ping", "-c", "3", host],  # Arguments as list — no shell involved
        capture_output=True,
        text=True
    )
    return result.stdout
```

### Fix 2: Replace os.system() with subprocess

```python
# 🚫 VULNERABLE
os.system(f"ping -c 1 {host}")

# ✅ SAFE
subprocess.run(["ping", "-c", "1", host])
```

### Fix 3: For Commands That Need Shell Features

```python
# ✅ SAFE — Use subprocess with pipes connected manually
import subprocess

# Instead of: subprocess.run("ps aux | grep python", shell=True)
p1 = subprocess.Popen(["ps", "aux"], stdout=subprocess.PIPE)
p2 = subprocess.Popen(["grep", "python"], stdin=p1.stdout, stdout=subprocess.PIPE)
p1.stdout.close()  # Allow p1 to receive SIGPIPE
output = p2.communicate()[0]
```

### Fix 4: Safe ffmpeg / Media Processing

```python
# ✅ SAFE — Pass arguments as list
import subprocess

def convert_video(input_file, output_format):
    # Never trust output_format either — validate it
    VALID_FORMATS = {'mp4', 'avi', 'mkv', 'webm'}
    if output_format not in VALID_FORMATS:
        raise ValueError(f"Invalid format: {output_format}")
    
    subprocess.run([
        "ffmpeg", "-i", input_file,
        "-f", output_format,
        f"output.{output_format}"
    ])
```

### Fix 5: For Hostname/IP Validation

```python
# ✅ SAFE — Validate input domain/ip before command execution
import re
import subprocess

def ping_host(host):
    # Validate hostname format before passing to command
    HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$')
    if not HOSTNAME_RE.match(host):
        raise ValueError(f"Invalid hostname: {host}")
    
    result = subprocess.run(
        ["ping", "-c", "3", host],
        capture_output=True,
        text=True,
        timeout=30
    )
    return result.stdout
```

---