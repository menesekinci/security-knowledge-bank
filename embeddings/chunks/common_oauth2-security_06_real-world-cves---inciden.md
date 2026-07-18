---
source: "common/oauth2-security.md"
title: "OAuth 2.0 Security — Implicit Grant, Redirect URI, CSRF, PKCE, Token Leakage"
heading: "Real-World CVEs & Incidents"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [checklist, common-vuln, cves, major, oauth, prevention, real-world, vibe, what]
chunk: 6/8
---

## Real-World CVEs & Incidents

| Vulnerability | CVE / Incident | Impact |
|---------------|---------------|--------|
| **Booking.com OAuth ATO** | Salt Labs 2023 | Account takeover via OAuth implementation flaw in social login |
| **Facebook OAuth ATO** | Y. Sammouda 2022 | Login CSRF via missing state validation on Facebook Login |
| **Microsoft/GitHub OAuth Redirection** | Proofpoint 2026 | Redirect URI abuse enables phishing and malware delivery |
| **Expo OAuth Vulnerability** | Salt Security 2023 | Hundreds of apps using Expo framework vulnerable to OAuth attack |
| **Google OAuth Login CSRF** | Bug bounty 2018 | Missing state in Google Sign-In flow enabled account takeover |
| **PayPal OAuth Scope Escalation** | Bug bounty 2019 | Scope validation bypass allowed elevated API access |
| **Keycloak redirect_uri Validation Bypass** | CVE-2023-6291 | URL-parsing desync bypassed allowed redirect hosts → authorization code / access token theft |
| **Slack OAuth Token Theft** | Bug bounty 2021 | Redirect URI path traversal enabled token interception |

### Case Study 1: Booking.com Account Takeover (2023)

Salt Labs discovered an OAuth implementation vulnerability in Booking.com's social login. The flaw allowed an attacker to **take over any user account** by manipulating the OAuth state parameter. The `state` parameter was generated client-side and not cryptographically bound to the session, enabling an attacker to:

1. Initiate OAuth login with their own Google account
2. Capture the `state` parameter
3. Trick victim into using the attacker's `state`
4. Bind attacker's social account to victim's Booking.com account

**Source:** https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com

### Case Study 2: Microsoft OAuth Redirection Abuse (2026)

Microsoft Threat Intelligence reported that threat actors were actively exploiting OAuth redirection mechanisms in government and public-sector organizations. The attack used:

1. Silent OAuth authentication flows with intentionally invalid scopes
2. Redirect URI manipulation to route tokens to attacker-controlled endpoints
3. Harvested tokens used for lateral movement and data exfiltration

This campaign affected **multiple government agencies** across North America and Europe.

**Source:** https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/

### Case Study 3: OAuth 2.0 Redirect URI Validation Flaws (2023 Research)

A large-scale study published in ACM (Innocenti et al., 2023) analyzed OAuth 2.0 implementations across **over 200 OAuth providers** and found that:

- **64% of providers** had inadequate redirect URI validation
- **27%** accepted redirect URIs with different hosts if the path matched
- **12%** allowed open redirect patterns in the redirect URI
- **8%** had no redirect URI validation at all

**Source:** https://dl.acm.org/doi/fullHtml/10.1145/3627106.3627140

---