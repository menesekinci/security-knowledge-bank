---
source: "languages/javascript/eval-injection.md"
title: "Eval Injection — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 4
total_chunks: 8
heading: "Vulnerable Code Example"
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