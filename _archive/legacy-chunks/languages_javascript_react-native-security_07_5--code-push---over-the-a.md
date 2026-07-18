---
source: "languages/javascript/react-native-security.md"
title: "React Native Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 7
total_chunks: 13
heading: "5. Code Push / Over-The-Air (OTA) Updates"
---

## 5. Code Push / Over-The-Air (OTA) Updates

### Vulnerability

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — No integrity check on OTA updates
import codePush from "react-native-code-push";

// Auto-updates without verification
codePush.sync({
  installMode: codePush.InstallMode.IMMEDIATE,  // 💀 No rollback option
  updateDialog: false,
  // 💀 No deployment key validation
});
```

**Secure Code:**
```javascript
// ✅ SECURE — Code Push with integrity checks
import codePush from "react-native-code-push";

codePush.sync({
  installMode: codePush.InstallMode.ON_NEXT_RESTART,
  mandatoryInstallMode: codePush.InstallMode.ON_NEXT_RESTART,
  updateDialog: {
    title: "Update available",
    mandatoryContinueButtonLabel: "Update now",
  },
  deploymentKey: Platform.select({
    ios: "IOS_DEPLOYMENT_KEY",
    android: "ANDROID_DEPLOYMENT_KEY",
  }),
  // ✅ Rollback on failure
  rollbackRetryOptions: {
    delay: 1000 * 60 * 5,  // Retry after 5 minutes
    maxRetryAttempts: 3,
  },
});
```

---