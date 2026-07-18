---
source: "languages/javascript/prototype-pollution.md"
title: "Prototype Pollution — JavaScript"
heading: "Secure Code Fix"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 5/8
---

## Secure Code Fix

### Fix 1: Safe Merge Without __proto__

```javascript
// ✅ SAFE — Explicit __proto__ check in merge
function safeMerge(target, source) {
  // Reject prototype pollution keys
  const BLACKLISTED_KEYS = ['__proto__', 'constructor', 'prototype'];
  
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (BLACKLISTED_KEYS.includes(key)) {
        continue;  // Skip dangerous keys
      }
      
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}
```

### Fix 2: Use Object.create(null) for Untrusted Keys

```javascript
// ✅ SAFE — Objects without prototype chain
const safeMap = Object.create(null);  // No __proto__, no prototype chain
safeMap['__proto__'] = 'value';       // Safe — just a regular property
console.log(safeMap['__proto__']);    // 'value' — no pollution
console.log(safeMap.isAdmin);         // undefined — no inheritance
```

### Fix 3: Use Safe Libraries

```javascript
// ✅ SAFE — Use lodash with fixed version
const _ = require('lodash');
// lodash >= 4.17.12 is safe (4.17.5 fixed _.merge; 4.17.12 also fixed _.defaultsDeep — CVE-2019-10744)
_.merge(defaultConfig, userInput);  // ✅ Has __proto__ protection

// Or use deepmerge library (built for this)
const deepmerge = require('deepmerge');
const config = deepmerge(defaults, userInput);  // ✅ Protects against pollution
```

### Fix 4: Freeze Object.prototype

```javascript
// ✅ SAFE — Prevent prototype mutation entirely
Object.freeze(Object.prototype);
// This prevents __proto__ assignment across the entire runtime
```

### Fix 5: JSON Schema Validation

```javascript
// ✅ SAFE — Validate JSON input against schema
const Ajv = require('ajv');
const ajv = new Ajv();

const configSchema = {
  type: 'object',
  properties: {
    port: { type: 'integer', minimum: 1024, maximum: 65535 },
    features: {
      type: 'object',
      properties: {
        darkMode: { type: 'boolean' }
      },
      additionalProperties: false  // No extra keys
    }
  },
  additionalProperties: false  // Rejects __proto__, constructor, etc.
};

app.post('/update', (req, res) => {
  const validate = ajv.compile(configSchema);
  if (!validate(req.body)) {
    return res.status(400).json({ error: 'Invalid config' });
  }
  // Safe to merge now — schema rejected dangerous keys
  safeMerge(defaultConfig, req.body);
});
```

### Fix 6: Use Map Instead of Plain Objects

```javascript
// ✅ SAFE — Map has no prototype pollution vector
const config = new Map();
config.set('__proto__', 'value');  // Safe — Map keys are separate from prototype
console.log(config.get('__proto__'));  // 'value'
console.log(config.isAdmin);           // undefined
```

---