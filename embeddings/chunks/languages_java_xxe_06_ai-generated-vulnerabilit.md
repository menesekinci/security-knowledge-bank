---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
heading: "AI-Generated Vulnerability: XXE in SOAP Web Services"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, parser, vulnerability, vulnerable]
chunk: 6/10
---

## AI-Generated Vulnerability: XXE in SOAP Web Services

```java
// AI-GENERATED — JAX-WS SOAP endpoint
@WebMethod
public String processData(String xmlData) {
    // BUG: AI-generated SOAP handlers often parse XML without protection
    // XXE in SOAP can read server files
}
```