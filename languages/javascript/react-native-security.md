# React Native Security Deep Dive

> **Category:** JavaScript / React Native Security Knowledge Bank  
> **Focus:** AsyncStorage risks, deep linking, WebView, Hermes engine, code push, certificate pinning  
> **Last Updated:** July 2026

---

## Overview

React Native applications share code between iOS and Android but introduce unique mobile security challenges. Unlike web apps, React Native apps run native code, store data on-device, and communicate with servers. Common AI-produced misconfigurations include storing sensitive data in AsyncStorage, insecure WebView configurations, and improper deep linking handling.

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

## 2. WebView — XSS and Remote Code Execution

### Vulnerability

WebView in React Native can execute JavaScript that has access to device APIs through the JS bridge.

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — WebView with no security restrictions
import { WebView } from "react-native-webview";

function ProfileView({ userContent }) {
  return (
    <WebView
      source={{ html: userContent }}         // 💀 Direct HTML injection
      javaScriptEnabled={true}               // 💀 JavaScript enabled
      allowFileAccess={true}                 // 💀 File system access
      allowUniversalAccessFromFileURLs={true} // 💀 Cross-origin file access
      mixedContentMode="always"              // 💀 Allow HTTP on HTTPS pages
      onMessage={(event) => {
        // 💀 Native method can be called from WebView JS
        invokeNativeMethod(event.data);
      }}
    />
  );
}
```

**Secure Code:**
```javascript
// ✅ SECURE — Restricted WebView
import { WebView } from "react-native-webview";
import { sanitizeHtml } from "./sanitizer";

function SecureWebView({ url }) {
  return (
    <WebView
      source={{ uri: url }}
      javaScriptEnabled={false}         // ✅ Disable JS if not needed
      allowFileAccess={false}           // ✅ No file access
      allowUniversalAccessFromFileURLs={false}
      mixedContentMode="never"          // ✅ Only HTTPS content
      originWhitelist={["https://*.example.com"]}  // ✅ Restrict allowed origins
      onShouldStartLoadWithRequest={(request) => {
        // ✅ Only allow navigation to trusted domains
        return request.url.startsWith("https://trusted.example.com");
      }}
    />
  );
}

// For rendered HTML content — use a restricted sandbox
function SafeHtmlRenderer({ html }) {
  const sanitized = sanitizeHtml(html, {
    allowedTags: ["b", "i", "em", "strong", "p", "br"],
    allowedAttributes: {},
  });

  return (
    <WebView
      source={{ html: sanitized }}
      javaScriptEnabled={false}
      originWhitelist={[]}
    />
  );
}
```

---

## 3. Deep Linking — URL Scheme Hijacking

### Vulnerability

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — No validation on deep links
// app.json
{
  "schemes": ["myapp"]  // 💀 Any app can register same scheme
}

// Linking handler — 💀 No URL validation
import { Linking } from "react-native";

useEffect(() => {
  // 💀 Processes ANY incoming URL
  Linking.addEventListener("url", ({ url }) => {
    const token = url.split("token=")[1];
    authenticateWithToken(token);  // 💀 No origin check
  });
}, []);
```

**Secure Code:**
```javascript
// ✅ SECURE — Universal Links / App Links + validation

// iOS: Use universal links (apple-app-site-association)
// Android: Use app links (assetlinks.json)

// app.json — Use universal links instead of custom schemes if possible
{
  "associatedDomains": ["applinks:trusted.example.com"]
}

// Linking handler with validation
import { Linking } from "react-native";

const TRUSTED_DOMAINS = ["trusted.example.com", "api.example.com"];

function isTrustedUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return TRUSTED_DOMAINS.includes(parsed.hostname) 
      && parsed.protocol === "https:";
  } catch {
    return false;
  }
}

useEffect(() => {
  Linking.addEventListener("url", ({ url }) => {
    if (!isTrustedUrl(url)) {
      console.warn("Ignored untrusted deep link:", url);
      return;
    }
    
    const params = new URL(url).searchParams;
    const token = params.get("token");
    if (token) {
      authenticateWithToken(token);
    }
  });
}, []);
```

### Common AI Misconfiguration

```javascript
// 💀 VULNERABLE — AI often generates custom scheme deep links without validation
// ChatGPT/Claude frequently produce:
Linking.openURL("myapp://login?token=" + token);
// This is vulnerable to URL scheme hijacking on both platforms
```

---

## 4. Hermes Engine Security

### JavaScript Injection

The Hermes engine precompiles JavaScript to bytecode. While this provides some protection against source code inspection, it doesn't prevent runtime injection.

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Dynamic code execution in Hermes
const userCode = await fetchUserScript();
// Hermes supports eval() — dangerous with untrusted input
eval(userCode);  // 💀 Code injection
```

**Secure Code:**
```javascript
// ✅ SECURE — Avoid dynamic code execution
// Hermes supports Function() constructor too — avoid both!

// Use sandboxed evaluation instead
// Or better — don't execute user code at all

// If you must evaluate expressions, use a safe expression parser
import { compileExpression } from "filtrex";

const safeExpr = compileExpression(userInput);
const result = safeExpr({ items: data });
```

### Hermes Debugger Exposure

```javascript
// 💀 VULNERABLE — Debugger enabled in production
// metro.config.js or .env
HERMES_DEBUGGER_ENABLED = true;  // 💀 Exposes bytecode debug interface
```

```javascript
// ✅ SECURE — Disable debugger in production builds
// .env.production
HERMES_DEBUGGER_ENABLED = false;

// metro.config.js
module.exports = {
  transformer: {
    minifierConfig: {
      mangle: { reserved: [] },  // Obfuscate production code
    },
  },
};
```

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

## 6. Certificate Pinning

### Vulnerability

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — No certificate validation
import axios from "axios";

const api = axios.create({
  baseURL: "https://api.example.com",
  // 💀 Default HTTPS client accepts any valid cert
});
```

**Secure Code:**
```javascript
// ✅ SECURE — Certificate pinning with react-native-ssl-pinning
import { fetch } from "react-native-ssl-pinning";

// iOS: Include .cer file in bundle
// Android: Include .cer file in raw resources

const response = await fetch("https://api.example.com/login", {
  method: "POST",
  body: JSON.stringify(payload),
  sslPinning: {
    certs: ["certificate_name"],  // Pin to specific certificate
  },
  headers: {
    "Content-Type": "application/json",
  },
});
```

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

## 8. Expo-Specific Security

```javascript
// 💀 VULNERABLE — Expo development mode in production
if (__DEV__) {
  // 💀 API calls should work without dev mode code
}

// ✅ SECURE — Remove development code from production builds
if (__DEV__) {
  console.log("Dev-only logging");
  // Production builds strip this block automatically
}
```

---

## 9. Version Recommendations

| Library | Version | Status | Notes |
|---------|---------|--------|-------|
| React Native | 0.79+ | ✅ Latest | Hermes enabled by default |
| react-native-webview | 14.x+ | ✅ Latest | Support for content blockers |
| react-native-keychain | 9.x+ | ✅ Secure storage | Biometric support |
| react-native-encrypted-storage | 4.x+ | ✅ Alternative secure storage |
| expo-secure-store | 14.x+ | ✅ For Expo projects |
| react-native-ssl-pinning | 1.6+ | ✅ Certificate pinning |

---

## 10. Common AI-Produced Misconfigurations

1. **Sensitive data in AsyncStorage** — AI frequently uses AsyncStorage for tokens
2. **WebView without restrictions** — `javaScriptEnabled`, `allowFileAccess` left at defaults
3. **Custom scheme deep linking without validation** — No URL origin verification
4. **`eval()` in Hermes** — Dynamic code execution with user input
5. **No certificate pinning** — API calls without TLS validation
6. **Clipboard exposure** — Auto-copying sensitive text
7. **Hardcoded API keys** — Embedding secrets in JS bundle
8. **Insecure OTA updates** — Code Push without integrity verification
9. **Debug mode in production** — Hermes debugger or dev tools exposed
10. **No biometric authentication** — Sensitive app functions without auth gate

---

## Verification / Source URLs

- React Native Security Docs: https://reactnative.dev/docs/security
- RNSEC Security Rules: https://www.rnsec.dev/docs/security-rules
- React Native Security Best Practices: https://spacetotech.com/blog/react-native-security
- react-native-keychain: https://github.com/oblador/react-native-keychain
- react-native-encrypted-storage: https://github.com/emeraldsanto/react-native-encrypted-storage
- React Native WebView Security: https://github.com/react-native-webview/react-native-webview
- OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/
