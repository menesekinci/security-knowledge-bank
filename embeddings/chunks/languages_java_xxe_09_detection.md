---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
heading: "Detection"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, parser, vulnerability, vulnerable]
chunk: 9/10
---

## Detection

```bash
# Find XML parser instantiation
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|TransformerFactory" src/

# Find XXE-vulnerable patterns (no features set)
grep -A5 "DocumentBuilderFactory.newInstance()" src/

# Find disallow-doctype-decl (properly configured)
grep -rn "disallow-doctype-decl" src/

# Use FindSecBugs
mvn com.h3xstream.findsecbugs:findsecbugs-plugin:findsecbugs
```