---
source: "common/engineering/zero-trust-architecture.md"
title: "Zero Trust Architecture"
heading: "6. Implementation Roadmap for Startups"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [beyondcorp, common-vuln, core, five, google, principles, table, what, zero]
chunk: 8/10
---

## 6. Implementation Roadmap for Startups

Zero Trust does not require Google-scale infrastructure. Startups can adopt Zero Trust principles incrementally, starting with the highest-impact controls.

### Phase 1: Identity Foundation (Days 1–30)

**Goal:** Establish identity as the new perimeter.

- [ ] Deploy an SSO provider (Okta, Azure AD, Google Workspace, Keycloak)
- [ ] Enforce MFA for *all* users (no exceptions)
- [ ] Remove shared accounts; every action is attributable to a person
- [ ] Use OIDC/OAuth 2.0 for application authentication (no shared API keys between services)
- [ ] Enable conditional access policies (block logins from unexpected geographies)

**Cost:** $0–$500/month (many SSO providers have free tiers for small teams)

### Phase 2: Device Basic Hygiene (Days 30–60)

**Goal:** Know what devices access your resources and enforce basic health.

- [ ] Enroll company devices in MDM or at minimum require disk encryption
- [ ] Require login from managed browsers (Chrome policy, device certificates)
- [ ] Set up device inventory — even a Google Sheet is better than nothing
- [ ] Block access from unregistered devices to production and sensitive admin panels

**Cost:** $0–$10/user/month (MDM free tiers for small teams)

### Phase 3: Network Segmentation (Days 60–90)

**Goal:** Restrict lateral movement in cloud environments.

- [ ] Implement cloud network security groups with least-privilege rules
- [ ] Database security groups: only allow traffic from the application tier
- [ ] No public-facing databases; use private subnets and bastion hosts
- [ ] Kubernetes: enable NetworkPolicies (default deny ingress)
- [ ] Production and non-production environments are completely separated

**Cost:** Infrastructure cost only (security groups and network policies are free in major clouds)

### Phase 4: Application Security (Days 90–180)

**Goal:** Every application enforces its own authorization.

- [ ] All services authenticate via mTLS or OIDC
- [ ] API gateways enforce authentication and rate limiting
- [ ] Deploy an internal developer portal with identity-aware proxy (OAuth2 Proxy + your SSO)
- [ ] Remove VPN requirements for accessing internal tools
- [ ] Implement CI/CD with short-lived credentials (OIDC-based cloud provider authentication)

**Cost:** Open-source proxies are free; managed services cost $20–$200/month

### Phase 5: Continuous Monitoring (Ongoing)

**Goal:** Detect and respond to anomalies in real time.

- [ ] Centralized logging with security-relevant schema (SIEM-lite: ELK, Grafana Loki, or a cloud SIEM)
- [ ] Alert on anomalous access patterns (first-time access, unusual volume, off-hours)
- [ ] Automate response: suspicious access → revoke session → alert security team
- [ ] Schedule periodic access reviews — every user, every permission reviewed quarterly
- [ ] Tabletop exercises: "What happens if a developer's laptop is compromised right now?"

**Cost:** $0–$500/month depending on volume and tooling

### Phase 6: Advanced Controls (Year 2+)

- Service mesh (Istio/Linkerd) for full east-west mTLS and policy enforcement
- Zero-standing-privileges for all human access
- Automated data classification and DLP
- BeyondCorp-style access proxy for all internal applications
- Full attack surface management program

### Startup-Specific Advice

- **Don't try to do it all at once** — Phase 1 (SSO + MFA) eliminates the highest-risk vulnerabilities immediately
- **Leverage cloud-native controls** — AWS IAM, GCP IAM, and Azure RBAC are Zero Trust by design when used correctly
- **SaaS-first** — replacing VPN with a product like Cloudflare Access or Tailscale is faster than building in-house
- **Security is a feature** — document your Zero Trust implementation in your SOC 2 or security questionnaire responses; it is a competitive advantage

---