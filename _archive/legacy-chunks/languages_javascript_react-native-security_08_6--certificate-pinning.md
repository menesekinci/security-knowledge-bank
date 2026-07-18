---
source: "languages/javascript/react-native-security.md"
title: "React Native Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 8
total_chunks: 13
heading: "6. Certificate Pinning"
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