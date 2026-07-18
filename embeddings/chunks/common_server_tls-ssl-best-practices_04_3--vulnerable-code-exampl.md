---
source: "common/server/tls-ssl-best-practices.md"
title: "TLS / SSL Best Practices for Web Servers"
heading: "3. Vulnerable Code Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, cves, explanation, implementation, real, secure, vulnerability, vulnerable]
chunk: 4/9
---

## 3. Vulnerable Code Examples

### 3.1 Python: Disabled Certificate Verification

```python
# ❌ VULNERABLE: No certificate verification — MitM possible
import requests
response = requests.get('https://api.example.com/data', verify=False)

# ❌ VULNERABLE: Implicitly trusting any cert
import urllib.request
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
response = urllib.request.urlopen('https://api.example.com', context=ctx)
```

### 3.2 Nginx: Weak TLS Configuration

```nginx
# ❌ VULNERABLE: Weak protocols and ciphers
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/ssl/cert.pem;          # Self-signed in production
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;              # ❌ TLSv1 and TLSv1.1 enabled
    ssl_ciphers RC4:HIGH:!aNULL:!eNULL:!EXPORT:!LOW;  # ❌ RC4 is completely broken
    ssl_prefer_server_ciphers on;
    # Missing ssl_certificate_trusted (no chain)
    # No HSTS
}
```

### 3.3 Java: Trust-All TrustManager

```java
// ❌ VULNERABLE: Trusts any certificate including self-signed
import javax.net.ssl.*;

TrustManager[] trustAll = new TrustManager[]{
    new X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[]{};
        }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
};

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAll, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

// All hostnames accepted — ❌
HostnameVerifier allHosts = (hostname, session) -> true;
HttpsURLConnection.setDefaultHostnameVerifier(allHosts);
```

### 3.4 Node.js: Incomplete Certificate Handling

```javascript
// ❌ VULNERABLE: No certificate authority chain
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
  // Missing: ca: fs.readFileSync('ca-chain.pem')
};

https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('hello world\n');
}).listen(443);

// ❌ VULNERABLE: RejectUnauthorized disabled
const requestOptions = {
  hostname: 'api.example.com',
  port: 443,
  path: '/data',
  rejectUnauthorized: false  // ❌ Accepts self-signed certs
};
```

### 3.5 Go: InsecureSkipVerify

```go
// ❌ VULNERABLE: Disables certificate validation
package main

import (
    "crypto/tls"
    "net/http"
)

func main() {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,  // ❌ Accepts any certificate
        },
    }
    client := &http.Client{Transport: tr}
    resp, _ := client.Get("https://api.example.com/data")
}
```

---