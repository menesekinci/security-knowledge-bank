---
source: "common/http-smuggling.md"
title: "HTTP Request Smuggling"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, smuggling, vibe, vulnerable, what]
chunk: 5/11
---

## Why Vibe Coding Makes This Worse

- **AI rarely configures HTTP parsers:** Generated code uses default server settings that may be inconsistent
- **AI sets up reverse proxies:** AI generates nginx/Apache configs but may mismatch parser behavior
- **AI-generated applications behind CDN:** Without understanding HTTP parsing differences
- **HTTP/1.1 keepalive:** Smuggling requires persistent connections — AI enables keepalive by default