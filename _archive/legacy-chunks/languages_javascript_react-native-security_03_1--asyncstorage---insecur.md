---
source: "languages/javascript/react-native-security.md"
title: "React Native Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 3
total_chunks: 13
heading: "1. AsyncStorage — Insecure Data Storage"
---

## 1. AsyncStorage — Insecure Data Storage

### Vulnerability

React Native's AsyncStorage stores data in **unencrypted plaintext**. On Android, it's stored in `/data/data/<package>/databases/` (accessible with root). On iOS, it's stored in SQLite databases in the app sandbox (accessible with jailbreak).

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Storing sensitive data in AsyncStorage
import AsyncStorage from "@react-native-async-storage/async-storage";

// Storing auth tokens
await AsyncStorage.setItem("auth_token", token);
await AsyncStorage.setItem("user_data", JSON.stringify({
  ssn: user.ssn,
  creditCard: user.credit_card,
  password: user.password,
}));
```

**Secure Code:**
```javascript
// ✅ SECURE — Use platform-specific secure storage
// Install: npm install react-native-keychain

import * as Keychain from "react-native-keychain";
import EncryptedStorage from "react-native-encrypted-storage";

// Store sensitive data in Keychain (iOS) / Keystore (Android)
await Keychain.setGenericPassword("auth_token", token, {
  service: "com.app.auth.token",
  accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE,
});

// Use EncryptedStorage for structured sensitive data
await EncryptedStorage.setItem("secure_user_data", JSON.stringify({
  name: user.name,
  email: user.email,
  // ❌ Never store SSN or credit card numbers on-device
}));

// AsyncStorage is still fine for non-sensitive data
await AsyncStorage.setItem("theme_preference", "dark");
await AsyncStorage.setItem("last_viewed_tutorial", "true");
```

### React Native Security Rules

Per [RNSEC](https://www.rnsec.dev/), AsyncStorage should only be used for:
- UI state (theme, app version)
- Non-sensitive user preferences
- Cache data that can be refetched

---