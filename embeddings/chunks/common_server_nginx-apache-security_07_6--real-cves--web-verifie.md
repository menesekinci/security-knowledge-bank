---
source: "common/server/nginx-apache-security.md"
title: "Web Server Security: Nginx, Apache & Caddy"
heading: "6. Real CVEs (Web-Verified via NVD)"
category: "common-vuln"
language: "common"
severity: "high"
tags: [common-vuln, config, explanation, proxy, reverse, secure, vulnerability, vulnerable]
chunk: 7/10
---

## 6. Real CVEs (Web-Verified via NVD)

The following CVEs have been verified against the National Vulnerability Database (NVD) at time of writing.

### Nginx CVEs

| CVE ID | CVSS | CWE | Description | Affected Versions |
|--------|------|-----|-------------|-------------------|
| [CVE-2024-24989](https://nvd.nist.gov/vuln/detail/CVE-2024-24989) | 7.5 High | CWE-476 | NULL Pointer Dereference in HTTP/3 QUIC module allows worker process termination via undisclosed requests. Not enabled by default, experimental. | Nginx OSS 1.25.3, Nginx Plus R31 |
| [CVE-2024-35200](https://nvd.nist.gov/vuln/detail/CVE-2024-35200) | 5.3 Medium | CWE-476 | HTTP/3 QUIC module crash via undisclosed HTTP/3 requests causing worker termination. | Nginx OSS 1.25.0–1.26.0, Nginx Plus R30–R31 P1 |
| [CVE-2024-7347](https://nvd.nist.gov/vuln/detail/CVE-2024-7347) | 4.7 Medium | CWE-125/CWE-126 | Out-of-bounds read in `ngx_http_mp4_module` via crafted MP4 file, causing worker memory over-read and termination. Requires `mp4` directive. | Nginx OSS 1.5.13–1.26.1, Nginx Plus R27–R32 |

### Apache HTTP Server CVEs

| CVE ID | CVSS | CWE | Description | Affected Versions |
|--------|------|-----|-------------|-------------------|
| [CVE-2024-38475](https://nvd.nist.gov/vuln/detail/CVE-2024-38475) | 9.1 Critical | CWE-116 | Improper escaping in `mod_rewrite` allows attackers to map URLs to filesystem locations, enabling code execution or source disclosure. **Active exploitation** (CISA KEV). | Apache 2.4.0–2.4.59 |
| [CVE-2024-40898](https://nvd.nist.gov/vuln/detail/CVE-2024-40898) | 7.5–9.1 | CWE-918 | SSRF in `mod_rewrite` on Windows allows NTLM hash leak to malicious servers via server/vhost context. | Apache 2.4.0–2.4.61 (Windows only) |
| [CVE-2024-39573](https://nvd.nist.gov/vuln/detail/CVE-2024-39573) | 7.5 High | CWE-20 | SSRF in `mod_rewrite` allowing unsafe RewriteRules to route requests through `mod_proxy` unexpectedly. | Apache 2.4.0–2.4.59 |
| [CVE-2024-38472](https://nvd.nist.gov/vuln/detail/CVE-2024-38472) | 7.5 High | CWE-918 | SSRF on Windows allowing NTLM hash leak via malicious requests or content. | Apache ≤2.4.59 (Windows) |
| [CVE-2024-47252](https://nvd.nist.gov/vuln/detail/CVE-2024-47252) | 7.5 High | CWE-116 | Insufficient escaping in `mod_ssl` allows untrusted SSL/TLS clients to inject escape characters into log files. | Apache 2.4.0–2.4.63 |

### Caddy CVEs

Caddy has a smaller CVE footprint due to its modern design and automatic HTTPS. Common issues relate to misconfiguration rather than software vulnerabilities.

| CVE ID | CVSS | CWE | Description |
|--------|------|-----|-------------|
| No recent server-core CVEs | — | — | Caddy's automatic TLS and secure defaults reduce attack surface. Most Caddy risks are configuration-based: debug mode, open admin endpoints, missing auth. |

---