---
source: "languages/java/xxe.md"
title: "XML External Entity (XXE) Processing"
category: "language-vuln"
language: "java"
chunk: 8
total_chunks: 10
heading: "Real CVEs"
---

## Real CVEs

- **CVE-2024-22257 (Spring Framework)**: CVSS 7.5 — XXE vulnerability in Spring Framework's XML parsing when using certain configurations of `XmlBeanDefinitionReader`. Could lead to information disclosure via external entity processing.
- **CVE-2023-34053 (Spring Framework)**: CVSS 8.1 — XXE vulnerability in Spring Framework's `Jaxb2XmlDecoder` when processing XML requests in Spring Web Services.
- **CVE-2022-22965 (Spring4Shell)**: While not primarily an XXE attack, Spring4Shell's exploitation could be amplified via XXE to read sensitive files from the server.
- **CVE-2021-22095 (VMware Tanzu)**: CVSS 7.5 — XXE vulnerability in Spring Cloud Gateway's XML parsing could allow an attacker to read arbitrary files from the server.