---
source: "languages/c-cpp/type-confusion.md"
title: "Type Confusion (C/C++)"
heading: "Real-World CVEs / References"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs / References

| CVE | Vulnerability | Impact | Ref |
|-----|--------------|--------|-----|
| CVE-2021-30517 | Type confusion in V8 < 90.0.4430.212 | RCE via crafted HTML page (CVSS 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-30517), [Chrome Release](https://chromereleases.googleblog.com/2021/05/stable-channel-update-for-desktop.html) |
| CVE-2021-30551 | Type confusion in V8 < 91.0.4472.101 | Exploited in the wild as 0-day; RCE via heap corruption (CVSS 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-30551), [Project Zero RCA](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-30551.html) |
| CVE-2023-5217 | Heap buffer overflow in libvpx vp8 encoding (type confusion chain) | Exploited in the wild; RCE (CVSS 8.8) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-5217), [Wiz Analysis](https://www.wiz.io/blog/cve-2023-4863-and-cve-2023-5217-exploited-in-the-wild) |
| CVE-2018-1038 | Windows kernel type confusion (Win7 SP1) | Elevation of privilege — logical type confusion in kernel object handling | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-1038), [XPN Exploit Blog](https://blog.xpnsec.com/total-meltdown-cve-2018-1038/) |
| CVE-2024-3159 | Out-of-bounds memory access in V8 < 123.0.6312.105 | Arbitrary read/write via crafted HTML — type confusion leading to OOB | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-3159) |
| [CWE-843](https://cwe.mitre.org/data/definitions/843.html) | Access of Resource Using Incompatible Type ('Type Confusion') | Category reference | |

Browser engine type confusion CVEs are routine — track [Chrome releases](https://chromereleases.googleblog.com/) and [V8 vulnerability database](https://v8.dev/docs/vulnerability-fixes).

---