---
source: "common/cloud-security/serverless-security.md"
title: "☁️ Serverless Security — AWS Lambda & Cloudflare Workers"
heading: "4. Real CVEs & Incidents"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, cves, explanation, real, table, vulnerability, vulnerable]
chunk: 6/9
---

## 4. Real CVEs & Incidents

### 4.1 AWS Lambda & API Gateway

| CVE / Incident | Description | Impact | Status |
|----------------|-------------|--------|--------|
| **CVE-2022-40897** (CVSS 5.9, CWE-1333) | Regular Expression Denial of Service (ReDoS) in setuptools `package_index.py` — a crafted package page / HTML causes catastrophic regex backtracking, hanging the process. Relevant to Lambda build/CI pipelines that resolve packages from an untrusted index | Denial of service (CPU exhaustion) during dependency resolution | Fixed in setuptools >= 65.5.1 |
| **CVE-2023-44487** | HTTP/2 Rapid Reset attack used against AWS API Gateway and CloudFront, causing DDoS via stream cancellation | DoS via resource exhaustion | AWS mitigated Oct 2023 |
| **Lambda Event Injection (GHSA)** | Unsanitized S3 event payloads processed by Lambda functions — validated by multiple security audits | Remote code execution via crafted S3 objects | Prevention via input validation |
| **Capital One Breach (2019)** | Exploited SSRF in a misconfigured WAF + Lambda IAM role with over-permissions — 100M+ records stolen | Massive data exfiltration | IAM least-practice adopted post-incident |

### 4.2 Cloudflare Workers

| CVE / Incident | Description | Impact | Status |
|----------------|-------------|--------|--------|
| **CVE-2023-2512** | workerd (Workers runtime) integer overflow in FormData API — `forEach()` reads from wrong memory location when FormData has >2³¹ elements | Potential memory corruption (exploitation unlikely due to 160GB RAM requirement) | Fixed in v1.20230419.0 |
| **CVE-2023-48230** | Cap'n Proto KJ HTTP WebSocket buffer underrun in Cloudflare Workers Runtime — writes constant 4-byte string out-of-bounds | Denial of Service (CRITICAL CVSS 9.8) | Fixed in Cap'n Proto 1.0.1.1 |
| **CVE-2024-49770** | oak middleware path traversal on Cloudflare Workers — encoded `/` as `%2F` bypasses hidden file protection | Read sensitive data, access server secrets (CVSS 7.7 HIGH) | Fixed in oak 17.1.3 |
| **CVE-2025-55152** | oak middleware DoS via crafted `x-forwarded-proto` and `x-forwarded-for` headers | Denial of Service (CVSS 5.3) | Fixed in oak 17.1.6 |
| **CVE-2022-36083** | JOSE library PBKDF2 implementation — attacker can set arbitrarily high `p2c` iteration count, causing CPU-bound DoS | Denial of Service on Cloudflare Workers (CVSS 5.3) | Fixed in jose v1.28.2, v2.0.6, v3.20.4, v4.9.2 |

### 4.3 General Serverless Incidents

| Incident | Year | Description |
|----------|------|-------------|
| **OWASP Serverless Top 10** | 2021+ | Catalog of the most critical serverless security risks including injection, broken authentication, and misconfiguration |
| **Serverless FormData Attacks** | 2023 | Attackers exploit large form submissions to trigger memory issues in serverless runtimes |
| **Event Injection via S3** | 2024 | Malicious objects uploaded to S3 trigger Lambda functions that process unsanitized event data, leading to RCE |

---