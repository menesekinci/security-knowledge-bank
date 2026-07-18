---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
category: "language-vuln"
language: "java"
chunk: 6
total_chunks: 10
heading: "AI-Generated Vulnerability: XXE in SOAP Web Services"
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