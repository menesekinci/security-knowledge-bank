---
source: "languages/javascript/eval-injection.md"
title: "Eval Injection — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 8
total_chunks: 8
heading: "Vibe Coding Red Flags"
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