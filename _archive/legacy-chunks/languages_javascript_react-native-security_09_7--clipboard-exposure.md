---
source: "languages/javascript/react-native-security.md"
title: "React Native Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 9
total_chunks: 13
heading: "7. Clipboard Exposure"
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