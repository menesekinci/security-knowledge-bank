---
source: "languages/javascript/eval-injection.md"
title: "Eval Injection — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 5
total_chunks: 8
heading: "Secure Code Fix"
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