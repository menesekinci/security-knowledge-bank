---
source: "languages/javascript/eval-injection.md"
title: "Eval Injection — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 3
total_chunks: 8
heading: "How AI / Vibe Coding Generates This"
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