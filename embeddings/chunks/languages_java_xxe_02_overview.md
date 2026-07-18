---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
heading: "Overview"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, parser, vulnerability, vulnerable]
chunk: 2/10
---

## Overview

XML External Entity (XXE) injection is a vulnerability that occurs when an XML parser processes user-supplied XML input containing references to external entities. Java's default XML parser configurations have historically been **insecure by default** — many standard Java XML parsers allow DTDs and external entity resolution unless explicitly disabled.