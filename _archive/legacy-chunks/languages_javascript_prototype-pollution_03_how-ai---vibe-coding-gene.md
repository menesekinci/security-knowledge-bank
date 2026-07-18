---
source: "languages/javascript/prototype-pollution.md"
title: "Prototype Pollution — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 3
total_chunks: 8
heading: "How AI / Vibe Coding Generates This"
---

## How AI / Vibe Coding Generates This

### 1. Recursive Object Merge (The #1 Source)

```javascript
// 🚫 VULNERABLE — AI-generated deep merge
function deepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);  // 💥 No __proto__ check!
    } else {
      target[key] = source[key];  // 💥 Direct assignment
    }
  }
  return target;
}

// Used in config merging, state management, API response handling
app.use((req, res, next) => {
  // Merges user config into app config
  req.config = deepMerge(defaultConfig, req.body);  // 💥 Prototype pollution
  next();
});
```

### 2. Spread Operator in Nested Objects

```javascript
// 🚫 VULNERABLE — AI-generated config merger
const config = { ...defaults, ...userInput };  // ⚠️ Only pollutes if userInput has __proto__ directly
// But if userInput is parsed from JSON: JSON.parse('{"__proto__":{"isAdmin":true}}')
// The spread IS vulnerable to prototype pollution
```

### 3. Object.assign() with Nested Objects

```javascript
// 🚫 VULNERABLE — AI-generated settings merger
function applySettings(newSettings) {
  // Object.assign is NOT recursive, but __proto__ at top level still pollutes
  Object.assign(globalConfig, newSettings);  // 💥 If newSettings.__proto__ is set
}
```

### 4. URL Query String to Object Conversion

```javascript
// 🚫 VULNERABLE — AI-generated query parser
function parseQueryString(query) {
  const result = {};
  query.split('&').forEach(pair => {
    const [key, value] = pair.split('=');
    // Attacker sends: __proto__[isAdmin]=true
    // This sets result.__proto__.isAdmin = "true"
    setNestedValue(result, key, decodeURIComponent(value));  // 💥
  });
  return result;
}
```

### 5. Express Body Parser with Merge

```javascript
// 🚫 VULNERABLE — AI-generated Express middleware
const express = require('express');
const app = express();

app.use(express.json());  // Parses JSON body

app.post('/update-config', (req, res) => {
  // If req.body contains {"__proto__": {"admin": true}}
  mergeConfig(app.config, req.body);  // 💥 Global prototype pollution
  res.send('OK');
});
```

### 6. Lodash merge() (Historical — CVE-2018-3721)

```javascript
// 🚫 VULNERABLE — AI-generated code using Lodash merge
const _ = require('lodash');

function mergeUserConfig(userConfig) {
  // Lodash _.merge was vulnerable before 4.17.5
  _.merge(defaultConfig, userConfig);  // 💥 Prototype pollution via __proto__
}
// Fixed in lodash@4.17.5+ — but AI may generate old versions
```

### Why AI Does This

- **`deepMerge` is a common interview question:** AI training data is full of recursive merge implementations
- **`Object.assign` and spread are idiomatic:** AI uses them constantly without security awareness
- **Config merging is ubiquitous:** AI config management code always merges user input with defaults
- **No understanding of `__proto__` as a special key:** AI treats it as a regular property name
- **JSON parsing is assumed safe:** AI doesn't know that `JSON.parse` preserves `__proto__` keys

---