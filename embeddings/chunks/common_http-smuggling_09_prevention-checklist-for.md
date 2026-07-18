---
source: "common/http-smuggling.md"
title: "HTTP Request Smuggling"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, smuggling, vibe, vulnerable, what]
chunk: 9/11
---

## Prevention Checklist for AI Prompts

```
✅ HTTP SMUGGLING PREVENTION:
- Use HTTP/2 or HTTP/3 exclusively (immune to CL/TE smuggling)
- Reject requests with both Content-Length and Transfer-Encoding headers
- Normalize Transfer-Encoding header — only accept "chunked"
- Disable HTTP/1.1 keepalive between proxies and backends
- Use a WAF with smuggling detection
- Keep reverse proxy and backend server software updated
- For nginx: add "proxy_set_header Connection '';"
```

---