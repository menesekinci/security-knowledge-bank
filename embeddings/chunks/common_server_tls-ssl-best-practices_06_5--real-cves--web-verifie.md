---
source: "common/server/tls-ssl-best-practices.md"
title: "TLS / SSL Best Practices for Web Servers"
heading: "5. Real CVEs (Web-Verified via NVD)"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, cves, explanation, implementation, real, secure, vulnerability, vulnerable]
chunk: 6/9
---

## 5. Real CVEs (Web-Verified via NVD)

The following CVEs have been verified against the National Vulnerability Database (NVD) at time of writing.

| CVE ID | CVSS | CWE | Description | Affected Software |
|--------|------|-----|-------------|-------------------|
| [CVE-2024-5535](https://nvd.nist.gov/vuln/detail/CVE-2024-5535) | 9.1 Critical | CWE-126 | OpenSSL `SSL_select_next_proto` buffer overread when called with an empty supported client protocols buffer. May cause crash or memory content leak to the peer. | OpenSSL (multiple versions) |
| [CVE-2024-47252](https://nvd.nist.gov/vuln/detail/CVE-2024-47252) | 7.5 High | CWE-116 | Apache HTTP Server `mod_ssl` insufficient escaping of user-supplied data allows untrusted SSL/TLS clients to insert escape characters into log files. Can be used to inject false log entries or exploit log parsers. | Apache HTTP Server 2.4.0–2.4.63 |
| [CVE-2023-2650](https://nvd.nist.gov/vuln/detail/CVE-2023-2650) | 6.5 Medium | CWE-770 | OpenSSL OBJ_obj2txt() DoS via specially crafted ASN.1 object identifiers. Processing large sub-identifiers has O(n²) time complexity, leading to notable delays affecting OCSP, PKCS7/SMIME, CMS, CMP/CRMF, TS, and X.509 certificate processing. | OpenSSL 3.0.0–3.0.8, 3.1.0–3.1.0, 1.1.1–1.1.1t, 1.0.2–1.0.2zg |
| [CVE-2026-48697](https://nvd.nist.gov/vuln/detail/CVE-2026-48697) | 7.4 High | CWE-295 | Missing TLS certificate verification in FastNetMon Community Edition. The `execute_web_request_secure()` function creates an SSL context without calling `set_verify_mode(verify_peer)`, allowing MitM attacks on outbound HTTPS connections. | FastNetMon Community ≤1.2.9 |

### Additional Historic TLS CVEs (Reference)

| CVE ID | Year | Description |
|--------|------|-------------|
| CVE-2016-2183 | 2016 | **Sweet32** — 3DES 64-bit block cipher collision attack |
| CVE-2014-3566 | 2014 | **POODLE** — SSLv3 padding oracle attack |
| CVE-2015-0204 | 2015 | **FREAK** — EXPORT-grade RSA downgrade attack |
| CVE-2015-4000 | 2015 | **Logjam** — DH parameter downgrade to 512-bit export |
| CVE-2016-0800 | 2016 | **DROWN** — Cross-protocol attack on SSLv2 |
| CVE-2019-1559 | 2019 | OpenSSL 1.0.2 — 1.1.1 padding oracle MitM |

---