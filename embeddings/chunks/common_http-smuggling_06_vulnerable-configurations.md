---
source: "common/http-smuggling.md"
title: "HTTP Request Smuggling"
heading: "Vulnerable Configurations"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, smuggling, vibe, vulnerable, what]
chunk: 6/11
---

## Vulnerable Configurations

### Nginx → Node.js

```nginx
# 🔴 VULNERABLE: nginx defaults may conflict with Node.js parsing
server {
    listen 80;
    location / {
        proxy_pass http://node_backend;
        proxy_http_version 1.1;
    }
}
```

### Apache → Tomcat

```apache
# 🔴 VULNERABLE: Apache and Tomcat parse Transfer-Encoding differently
<VirtualHost *:80>
    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/
</VirtualHost>
```