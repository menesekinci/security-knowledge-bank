---
source: "languages/go/ssrf.md"
title: "SSRF — net/http, Custom Transports, and Server-Side Request Forgery"
heading: "Real CVEs"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [advanced, code, cves, go, language-vuln, overview, real, ssrf, vulnerable]
chunk: 6/8
---

## Real CVEs

- **CVE-2022-39383 (KubeVela / VelaUX APIServer, CVSS 6.5)**: A **blind SSRF** in the VelaUX API server. When Helm Chart was used as a component delivery method, the warehouse (repository) request address was not restricted, so a low-privileged attacker could point it at internal resources and force the server to make requests on their behalf. Fixed in KubeVela 1.5.9 and 1.6.2.
- **CVE-2026-58404 (Hugo, CVSS 6.8)**: An **SSRF with cloud-metadata exposure**. Hugo's `security.http.urls` deny policy only blocked loopback, internal, and metadata addresses written in dotted-decimal IPv4 notation; alternate IPv4 encodings (integer, hexadecimal, octal) bypassed the check, letting `resources.GetRemote` reach blocked services — including `169.254.169.254` metadata endpoints — during template processing (dangerous in hosted/CI builds). Exactly the decimal-only-filter mistake this page warns about. Fixed in Hugo 0.163.1.