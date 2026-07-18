---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
category: "language-vuln"
language: "java"
chunk: 2
total_chunks: 10
heading: "Overview"
---

## Overview

XML External Entity (XXE) injection is a vulnerability that occurs when an XML parser processes user-supplied XML input containing references to external entities. Java's default XML parser configurations have historically been **insecure by default** — many standard Java XML parsers allow DTDs and external entity resolution unless explicitly disabled.