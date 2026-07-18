---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
category: "language-vuln"
language: "java"
chunk: 4
total_chunks: 10
heading: "Why AI Generates XXE-Vulnerable Java Code"
---

## Why AI Generates XXE-Vulnerable Java Code

LLMs frequently use `DocumentBuilderFactory` or `SAXParser` without configuring them securely:

```java
// AI-GENERATED — vulnerable XML parser
public String parseXml(String xmlData) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // BUG: No XXE protection configured!
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
    // XXE succeeds — attacker reads local files
}
```