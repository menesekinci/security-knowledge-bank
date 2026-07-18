# lollms eval() Code Injection (CVE-2024-6982) — Python

## 📅 When Did It Happen?
2024 (CVE-2024-6982, parisneo/lollms fixed in 9.10)

## 🎯 Target System
lollms (Lord of Large Language Models) — a popular web UI / framework for running LLMs. Its "Calculate" function evaluated user-supplied expressions with Python's `eval()` inside an insufficiently sandboxed environment.

## 🔴 What Happened?
CVE-2024-6982 is a critical **code injection / remote code execution** vulnerability (CWE-94) in parisneo/lollms. The Calculate function passed user-supplied input to `eval()` and relied on a weak sandbox to keep it safe.

**How it worked:**
1. lollms received an "expression" from the user and passed it to `eval()`
2. The sandbox tried to block dangerous names, but the restriction was incomplete
3. An attacker bypassed it by loading the `os` module through `_frozen_importlib.BuiltinImporter`, then executed arbitrary OS commands
4. This gave full RCE in the process context — system access and data leakage

**Similar case:** Over the years, countless web applications have been compromised through the misuse of Python functions like `eval()`, `exec()`, `os.system()`, `subprocess.Popen(shell=True)`, and `pickle.load()`.

## 🧠 Root Cause
1. **Use of eval() / exec()** — user input is passed directly to eval/exec
2. **Lack of input sanitization** — code content is processed without being cleaned
3. **Python's dynamic nature** — eval() and exec() can execute any Python expression
4. **Safe alternatives not used** — AST (Abstract Syntax Tree) parsers, interpreters, or sandboxes were not used; eval/exec was preferred instead

## 💥 Impact
- **Full RCE** — ability to execute any command on the server
- Data leakage, system compromise, lateral movement
- CVSS score: 8.4 (High) — CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- Affects lollms deployments exposing the Calculate function

## 🔧 How Was It Fixed?
- lollms patched in version 9.10
- The sandbox around the Calculate function was hardened / the unsafe `eval()` path removed
- Dangerous builtins and import machinery blocked from the evaluation namespace

## 🎓 Lessons Learned
1. **Never use eval() and exec()** — especially with user input. If they must be used, ensure the input is completely trusted.
2. **Use AST (Abstract Syntax Tree)** — if code parsing is needed, the `ast` module is safe
3. **Input sanitization** — all user inputs must be sanitized
4. **Sandboxing** — if dynamic code execution is required, use isolated environments like Docker or gVisor
5. **Security scanning** — automatically detect `eval()`, `exec()` calls with tools like `bandit`, `semgrep`

## Vibe Coding Connection: How this error can be reproduced in AI code generation
AI easily responds to prompts like "calculate a mathematical expression" or "run a formula written by the user" with `eval(user_input)`. There are many "simple solutions" using eval() in AI's training data. For example: `result = eval(input("Expression: "))` — AI frequently generates this pattern. When asking AI for calculator or formula evaluation code, make sure it does not use `eval()`. Safe alternatives: `ast.literal_eval()` (evaluates only simple types) or the `simpleeval` library.

## 🔗 Source / Reference (URL)
- https://nvd.nist.gov/vuln/detail/CVE-2024-6982
- https://github.com/ParisNeo/lollms (parisneo/lollms — Calculate function eval RCE, fixed in 9.10)
