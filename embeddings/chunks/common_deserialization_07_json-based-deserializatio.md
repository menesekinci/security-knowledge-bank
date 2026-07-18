---
source: "common/deserialization.md"
title: "Insecure Deserialization — Pickle, YAML, Java Serialization, JSON Attacks"
heading: "JSON-Based Deserialization Attacks"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, deserialization, java, pickle, python, vibe, what, yaml]
chunk: 7/10
---

## JSON-Based Deserialization Attacks

While JSON itself is safe, **JSON parsing with additional features** can be dangerous.

### Vulnerable Patterns

```javascript
// 🔴 VULNERABLE: eval-based "JSON parsing"
const data = eval('(' + userInput + ')');  // Evaluates arbitrary JS!

// 🔴 VULNERABLE: reviver function that executes code
const data = JSON.parse(userInput, (key, value) => {
    if (typeof value === 'string' && value.startsWith('__proto__')) {
        // Dangerous — but still, JSON.parse is safe by default
    }
    return value;
});

// 🔴 VULNERABLE: Node.js circular JSON that causes DoS
function serialize(obj) {
    return JSON.parse(JSON.stringify(obj)); // Safe for data
}
```

### Prototype Pollution via JSON

```javascript
// Attacker sends: {"__proto__": {"admin": true}}
const config = JSON.parse(userInput);
// If the application merges this with another object:
Object.assign(app.config, config);
// app.config now has admin:true from __proto__ pollution
```

**✅ Fixed:**
```javascript
// Use Object.create(null) for configs
const config = Object.assign(Object.create(null), JSON.parse(userInput));

// Or use safe merge
function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor') continue;
        target[key] = source[key];
    }
    return target;
}
```

---