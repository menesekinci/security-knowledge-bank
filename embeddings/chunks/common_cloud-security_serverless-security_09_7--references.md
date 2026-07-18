---
source: "common/cloud-security/serverless-security.md"
title: "☁️ Serverless Security — AWS Lambda & Cloudflare Workers"
heading: "7. References"
category: "cloud-security"
language: "common"
severity: "high"
tags: [cloud-security, code, cves, explanation, real, table, vulnerability, vulnerable]
chunk: 9/9
---

## 7. References

### AWS Lambda Security
- [AWS Lambda Security Documentation](https://docs.aws.amazon.com/lambda/latest/dg/security.html)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [AWS IAM Least Privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)
- [AWS API Gateway Security](https://docs.aws.amazon.com/apigateway/latest/developerguide/security.html)
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)

### Cloudflare Workers Security
- [Cloudflare Workers Security Model](https://developers.cloudflare.com/workers/reference/security-model/)
- [Cloudflare Workers Best Practices](https://developers.cloudflare.com/workers/best-practices/)
- [Workers Environment Variables & Secrets](https://developers.cloudflare.com/workers/configuration/environment-variables/)
- [Cloudflare Workers Runtime API](https://developers.cloudflare.com/workers/runtime-apis/)

### CVEs
- [CVE-2023-2512 — Cloudflare workerd FormData overflow](https://nvd.nist.gov/vuln/detail/CVE-2023-2512)
- [CVE-2023-48230 — Cap'n Proto KJ HTTP buffer underrun](https://nvd.nist.gov/vuln/detail/CVE-2023-48230)
- [CVE-2024-49770 — oak middleware path traversal](https://nvd.nist.gov/vuln/detail/CVE-2024-49770)
- [CVE-2025-55152 — oak middleware DoS](https://nvd.nist.gov/vuln/detail/CVE-2025-55152)
- [CVE-2022-36083 — JOSE PBKDF2 DoS](https://nvd.nist.gov/vuln/detail/CVE-2022-36083)

### General Serverless Security
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
- [OWASP Serverless Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Serverless_Security_Cheat_Sheet.html)
- [Cloudflare Workers Security Blog](https://blog.cloudflare.com/tag/security/)
- [Capital One Breach Analysis](https://www.aboutamazon.com/news/aws/amazon-remediation-and-shareholder-impact-disclosures)

---

> **Severity: 🔴 High** — Serverless misconfigurations are the #1 cause of cloud data breaches. AI-generated serverless code is disproportionately vulnerable due to over-permissioned roles and missing authentication.