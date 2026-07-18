---
source: "common/business-logic.md"
title: "Business Logic Vulnerabilities"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [business, checklist, common, common-vuln, detection, prevention, strategies, vibe, what]
chunk: 7/8
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Smart Coupons for WooCommerce (< 2.3.0) — coupon abuse | CVE-2026-45438 | Missing Authorization (CWE-862): unauthenticated users mint high-value coupons — CVSS 7.5 (v3.1) |
| WooCommerce PayPal Payments (≤ 4.0.1) — payment-flow bypass | CVE-2026-9284 | Missing Authorization (CWE-862): unauthenticated order manipulation / mark order paid without a real PayPal capture — CVSS 8.2 (v3.1) |
| Starbucks gift cards — race-condition double-spend | N/A (no CVE — bug bounty) | Concurrent balance transfers duplicate funds, creating money from nothing (E. Homakov, 2015) |
| Stripe promotion code — redemption-limit bypass | N/A (no CVE — bug bounty) | Race condition lets a single-use promo code be redeemed past its limit (HackerOne #1717650) |
| Instacart — coupon redemption race condition | N/A (no CVE — bug bounty) | Parallel requests stack the same coupon for near-unlimited discount (HackerOne #157996) |

---