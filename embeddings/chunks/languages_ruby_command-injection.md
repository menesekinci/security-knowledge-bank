---
source: "languages/ruby/command-injection.md"
title: "🔴 Ruby Command Injection"
category: "language-vuln"
language: "ruby"
severity: "critical"
tags: [dangerous, example, language-vuln, open3, ruby, rule, using]
---

# 🔴 Ruby Command Injection

## Example (Dangerous)
```ruby
# 💀 VULNERABLE:
host = params[:host]
result = `ping -c 1 #{host}`  # Backtick = shell_exec!
# host = "127.0.0.1; rm -rf /" → 💀

# ✅ SECURE:
host = params[:host]
# 1. Input validation:
raise "Invalid host" unless host.match?(/\A[\w.-]+\z/)
# 2. Secure with Open3:
stdout, stderr, status = Open3.capture3("ping", "-c", "1", host)
```

## Using Open3
```ruby
require 'open3'

# ✅ Secure — array form:
stdout, stderr, status = Open3.capture3("ping", "-c", "1", host)

# ❌ Dangerous — string form:
stdout = `ping -c 1 #{host}`      # Backtick
stdout = %x(ping -c 1 #{host})    # %x
system("ping -c 1 #{host}")       # system
exec("ping -c 1 #{host}")         # exec
Open3.capture3("ping -c 1 #{host}")  # String form!
```

## Rule
- Use the array form (`Open3.capture3("cmd", "arg1", "arg2")`)
- Backtick `` ` ``, `%x()`, `system()`, `exec()` string form → DANGEROUS
- Perform input validation (whitelist via regex)

---

**Severity: 🔴 Critical** — RCE.
