---
source: "common/prototype-pollution.md"
title: "Prototype Pollution"
heading: "Fixed Code Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, fixed, prevention, vibe, vulnerable, what]
chunk: 5/8
---

## Fixed Code Examples

### Safe Merge Function

```javascript
// ✅ SAFE: prevent prototype pollution in merge
function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        // Skip dangerous keys
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }

        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

### Use Object.create(null) for Maps/Dictionaries

```javascript
// ✅ SAFE: create objects with no prototype chain
const safeConfig = Object.create(null);  // No __proto__ at all
safeConfig.port = 3000;

// Merge into this safe object
Object.assign(safeConfig, JSON.parse(userInput));
// If userInput has __proto__, assign() modifies the __proto__
// but since safeConfig has no prototype, it's just a regular property
```

### Use Map Instead of Object

```javascript
// ✅ SAFE: Map is not vulnerable to prototype pollution
const config = new Map();
config.set('port', 3000);

const userInput = JSON.parse('{"__proto__": {"admin": true}}');
for (const [key, value] of Object.entries(userInput)) {
    config.set(key, value);  // Stored in Map, not on prototype
}
// config.get('admin') → true (as a key in the map, not as a prototype)
// But: {}.admin → undefined (prototype not polluted!)
```

### Safe Version Checking on Input

```javascript
// ✅ SAFE: strip dangerous keys before any merge
function sanitizeKeys(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;

    const safe = {};
    for (const [key, value] of Object.entries(obj)) {
        if (key === '__proto__' || key === 'constructor') continue;
        safe[key] = sanitizeKeys(value);
    }
    return safe;
}

const cleanInput = sanitizeKeys(JSON.parse(userInput));
```

### Use Libraries That Are Prototype-Pollution Safe

```javascript
// ✅ SAFE: modern lodash (4.17.21+) is patched
const _ = require('lodash');
const result = _.defaultsDeep(userInput, defaults);  // Patched version

// ✅ SAFE: immer (immutable state)
const { produce } = require('immer');
const nextState = produce(baseState, draft => {
    // immer uses proxies, not direct property assignment
});
```

---