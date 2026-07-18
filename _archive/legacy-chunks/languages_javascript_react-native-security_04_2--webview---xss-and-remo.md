---
source: "languages/javascript/react-native-security.md"
title: "React Native Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 4
total_chunks: 13
heading: "2. WebView — XSS and Remote Code Execution"
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