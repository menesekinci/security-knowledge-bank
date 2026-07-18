---
source: "common/http-smuggling.md"
title: "HTTP Request Smuggling"
heading: "How It Works"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common, common-vuln, configurations, smuggling, vibe, vulnerable, what]
chunk: 3/11
---

## How It Works

HTTP/1.1 supports two ways to specify request body length:
- **Content-Length (CL):** `Content-Length: 13` — exactly 13 bytes
- **Transfer-Encoding (TE):** `Transfer-Encoding: chunked` — body is split into chunks

When front-end and back-end disagree on which header to trust, smuggling occurs.