---
source: "common/cors-deep.md"
title: "CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs"
heading: "Real-World CVEs & Incidents"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [coding, common-vuln, cors, headers, vibe, vulnerability, what]
chunk: 8/10
---

## Real-World CVEs & Incidents

| Vulnerability | CVE / Incident | Impact |
|---------------|---------------|--------|
| **Feast CORS Auth Bypass** | CVE-2024-11602 | Unauthenticated API access due to permissive CORS |
| **PayPal CORS Data Theft** | Bug bounty 2019 | Reflected origin with credentials → account data exfiltrated |
| **Shopify CORS + CSRF Combo** | Bug bounty 2020 | Wildcard CORS on admin API allowed unauthorized actions |
| **GitHub Enterprise CORS** | Bug bounty 2021 | Misconfigured CORS exposed internal API data |
| **Coinbase CORS Misconfig** | Bug bounty 2022 | Reflected origin on authenticated endpoints |
| **Zoom CORS + SSRF Chain** | Bug bounty 2020 | CORS misconfig amplified internal network scanning |
| **Flask-CORS Private Network** | CVE-2024-6221 | `Access-Control-Allow-Private-Network` set to `true` by default → private/internal network resources exposed to cross-origin requests |

### Case Study 1: PayPal CORS Data Exfiltration (2019)

A researcher discovered that PayPal's `paypal.com` reflected the `Origin` header in `Access-Control-Allow-Origin` on an authenticated API endpoint:

```
GET /myaccount/api/ HTTP/1.1
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

The researcher created a page that would:
1. Lure PayPal users to `evil.com`
2. The page would make authenticated fetch requests to PayPal's API
3. The browser would allow reading the response due to CORS
4. Exfiltrated account data to attacker's server

**Bounty:** $10,000+
**Source:** PortSwigger Research, bug bounty disclosure

### Case Study 2: CVE-2024-11602 — Feast CORS Vulnerability

A critical vulnerability in the Feast feature store platform allowed unauthenticated attackers to bypass CORS restrictions:

1. The server returned `Access-Control-Allow-Origin` with values that permitted attacker-controlled origins
2. Combined with permissive `Access-Control-Allow-Credentials`, this allowed cross-origin data theft
3. Attackers could exfiltrate sensitive feature store data through the victim's browser

**Source:** https://www.sentinelone.com/vulnerability-database/cve-2024-11602/

### Case Study 3: Internal Network CORS Scanning (PortSwigger Research)

PortSwigger Research demonstrated how CORS misconfigurations can be chained to scan internal networks. When internal tools (Jenkins, Grafana, Kibana) have permissive CORS, an attacker's website visited by an internal user can:

1. Scan open ports on `10.0.0.0/8` via CORS timing attacks
2. Access internal API endpoints (authenticated via the user's session cookies)
3. Exfiltrate internal tool data

**Source:** https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties

---