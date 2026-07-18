---
source: "languages/python/eval-exec.md"
title: "eval(), exec(), compile() Dangers"
heading: "Secure Code Fix"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, cves, explanation, language-vuln, prevention, python, real-world, secure, vulnerability]
chunk: 4/7
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