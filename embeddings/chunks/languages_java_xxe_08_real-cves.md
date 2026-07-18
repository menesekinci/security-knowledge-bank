---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
heading: "Real CVEs"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, parser, vulnerability, vulnerable]
chunk: 8/10
---

## Real CVEs

- **CVE-2016-3720 (FasterXML jackson-dataformat-xml)**: CVSS 9.8 — XML External Entity (XXE) vulnerability in `XmlMapper` in jackson-dataformat-xml up to and including 2.7.3. Because the underlying XML input factory did not disable external entities, deserializing attacker-supplied XML could read local files or perform SSRF. Fixed in 2.7.4 / 2.8.0.
- **CVE-2021-33813 (JDOM)**: CVSS 7.5 — XXE issue in `SAXBuilder` in JDOM through 2.0.6. A crafted XML document (e.g. in an HTTP request) triggers external entity / DTD processing, enabling denial of service (and information disclosure depending on configuration). Affected downstreams included Apache Solr and Apache Tika. Fixed in JDOM 2.0.6.1.
- **CVE-2022-40152 (Woodstox)**: CVSS 7.5 — Applications using the Woodstox XML parser (FasterXML `woodstox-core`) before 5.4.0 / 6.4.0 are vulnerable to a denial-of-service crash (stack overflow) when DTD support is enabled and the parser runs on user-supplied input. A classic DTD/entity-expansion resource-exhaustion vector. Fixed in 6.4.0 (and 5.4.0).