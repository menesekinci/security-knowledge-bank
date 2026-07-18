---
source: "common/ssrf.md"
title: "Server-Side Request Forgery (SSRF)"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [cloud, code, common-vuln, fixed, metadata, vibe, vulnerable, what]
chunk: 3/10
---

## Why Vibe Coding Makes This Worse

- **AI loves "fetch this URL":** AI-generated code often accepts URLs from user input for profile pictures, document previews, webhook callbacks, feed imports
- **AI doesn't validate redirects:** Follows HTTP redirects to internal IPs
- **AI doesn't restrict protocols:** Allows `file://`, `gopher://`, `dict://` protocols
- **Cloud-native defaults:** AI generates code for cloud VMs without awareness of metadata endpoints