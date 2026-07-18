---
source: "common/zero-day.md"
title: "Zero-Day Vulnerabilities (0-day) and Patch Lag (n-day)"
heading: "Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] Maintain SBOM for every deployable artifact; store with release metadata
- [ ] CI fails on High/Critical with documented exception process (time-boxed)
- [ ] Patch SLO defined by exposure (internet-facing vs internal) and severity
- [ ] Base images rebuilt on a calendar **and** on CVE triggers
- [ ] Inventory: what runs Log4j, what runs file-transfer appliances, what is EOL OS
- [ ] Segment high-value systems; limit egress from app tiers (reduces exploit usefulness)
- [ ] Virtual patch / WAF playbooks ready before you need them
- [ ] AI-generated code reviewed with SCA + secret scan + SAST, not “looks fine”
- [ ] Training data lag awareness: verify library versions against NVD/OSV at PR time
- [ ] Tabletop: “Log4Shell-class event tomorrow — who patches what in 24h?”
- [ ] Monitor CISA KEV (Known Exploited Vulnerabilities) and prioritize those first
- [ ] No exploit development in product repos; use vendor patches and official remediations

---