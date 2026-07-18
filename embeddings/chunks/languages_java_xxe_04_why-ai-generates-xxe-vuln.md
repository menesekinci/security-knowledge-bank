---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
heading: "Why AI Generates XXE-Vulnerable Java Code"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, parser, vulnerability, vulnerable]
chunk: 4/10
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