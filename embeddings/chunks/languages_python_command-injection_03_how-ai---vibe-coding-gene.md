---
source: "languages/python/command-injection.md"
title: "Command Injection — Python"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

### 1. os.system() for "Simple" Commands

```python
# 🚫 VULNERABLE — AI-generated system administration
import os

def ping_host(host):
    # AI reaches for os.system() — easiest path
    response = os.system(f"ping -c 4 {host}")  # 💥
    return response == 0
```

### 2. subprocess with shell=True

```python
# 🚫 VULNERABLE — AI-generated subprocess call
import subprocess

def run_command(cmd):
    # AI uses shell=True for piping/redirection
    result = subprocess.run(
        cmd, 
        shell=True,  # 💥 Shell injection
        capture_output=True,
        text=True
    )
    return result.stdout
```

### 3. curl/wget for Download Functions

```python
# 🚫 VULNERABLE — AI-generated download helper
import subprocess

def download_file(url, output_path):
    # AI constructs curl command with user input
    cmd = f"curl -o {output_path} {url}"  # 💥
    subprocess.run(cmd, shell=True)
```

### 4. Image/Video Processing with User Input

```python
# 🚫 VULNERABLE — AI-generated media processing
import subprocess

def convert_video(input_file, output_format):
    cmd = f"ffmpeg -i {input_file} -f {output_format} output.{output_format}"  # 💥
    subprocess.run(cmd, shell=True)
```

### 5. Git Operations in AI-Generated DevOps Scripts

```python
# 🚫 VULNERABLE — AI-generated git automation
import subprocess

def checkout_branch(branch_name):
    subprocess.run(f"git checkout {branch_name}", shell=True)  # 💥
```

### Why AI Does This

- **`os.system()` and `subprocess(shell=True)` are 1-liners:** AI optimizes for brevity
- **Shell features are assumed needed:** Pipes, redirects, and env vars make `shell=True` seem necessary
- **No token economy for security:** The AI has finite token output; adding shell escaping costs tokens
- **Command execution patterns are overrepresented:** Tutorials use `os.system()` extensively

---