---
source: "languages/c-cpp/uninitialized-memory.md"
title: "Uninitialized Memory Use (C/C++)"
heading: "Real-World CVEs / References"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs / References

| CVE / ref | Relevance |
|-----------|-----------|
| [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) | Heartbleed — out-of-bounds read of OpenSSL heap; iconic **memory content disclosure** class (bounds, not classic uninit, but same impact taxonomy: secret material leaves process) |
| [CVE-2015-0235](https://nvd.nist.gov/vuln/detail/CVE-2015-0235) | GHOST — glibc; native library memory safety impact |
| [CVE-2015-7547](https://nvd.nist.gov/vuln/detail/CVE-2015-7547) | glibc `getaddrinfo` — stack buffer issues in widely deployed C code |
| [CWE-457](https://cwe.mitre.org/data/definitions/457.html) | Use of Uninitialized Variable |
| [CWE-908](https://cwe.mitre.org/data/definitions/908.html) | Use of Uninitialized Resource |
| Numerous kernel CVEs | Uninitialized struct padding leaked to userspace (search NVD for “uninitialized” + Linux kernel) |

Heartbleed is included as the industry reference for **catastrophic secret leakage from native memory mishandling**; pair with pure CWE-457 cases in your own code reviews.

---