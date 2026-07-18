---
source: "languages/javascript/react-native-security.md"
title: "React Native Security Deep Dive"
heading: "7. Clipboard Exposure"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [asyncstorage, deep, engine, hermes, insecure, javascript, language-vuln, linking, overview, webview]
chunk: 9/13
---

## 7. Clipboard Exposure

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Auto-copying sensitive data to clipboard
import Clipboard from "@react-native-clipboard/clipboard";

function showPassword({ password }) {
  // 💀 Sensitivity displayed in plaintext AND copied to system clipboard
  Clipboard.setString(password);
  alert("Password copied to clipboard!");  
  // 💀 Other apps can read the clipboard
}
```

**Secure Code:**
```javascript
// ✅ SECURE — Mask sensitive data, inform about clipboard
import Clipboard from "@react-native-clipboard/clipboard";

function showPassword({ password }) {
  // Don't auto-copy
  alert("Password has been generated. You can long-press to copy.");

  // If clipboard use is absolutely necessary, clear it after
  Clipboard.setString(password);
  setTimeout(() => {
    Clipboard.setString("");  // Clear clipboard after 30 seconds
  }, 30000);
}
```

---