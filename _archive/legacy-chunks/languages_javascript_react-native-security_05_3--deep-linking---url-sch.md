---
source: "languages/javascript/react-native-security.md"
title: "React Native Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 5
total_chunks: 13
heading: "3. Deep Linking — URL Scheme Hijacking"
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