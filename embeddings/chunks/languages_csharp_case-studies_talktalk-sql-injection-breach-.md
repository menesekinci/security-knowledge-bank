---
source: "languages/csharp/case-studies/talktalk-sql-injection-breach-2015.md"
title: "TalkTalk Data Breach: SQL Injection Attack on Legacy Systems"
category: "case-study"
language: "csharp"
severity: "high"
tags: [attack, case-study, cause, csharp, data, exposed, overview, perpetrators, root]
---

# TalkTalk Data Breach: SQL Injection Attack on Legacy Systems

**Language:** C# / .NET (Legacy ASP.NET Web Forms — Tiscali acquisition pages)
**Vulnerability Type:** SQL Injection
**Date:** October 2015
**Impact:** 156,959 customer records exposed, £400,000 fine

## Overview

In October 2015, British telecommunications provider **TalkTalk** suffered one of the UK's most notorious data breaches. Several attackers exploited **SQL injection vulnerabilities** in three legacy webpages that TalkTalk had inherited from its 2009 acquisition of Tiscali UK. Multiple individuals were later convicted — including **Matthew Hanley** and **Connor Allsopp** (both in their early twenties), while **Elliott Gunton** used the automated tool **sqlmap** to probe the pages for vulnerabilities. The breach exposed the personal data of 156,959 customers, including bank account numbers and sort codes of 15,656 customers.

The attack made international headlines, triggered a House of Commons inquiry, and resulted in the ICO's largest-ever fine at the time (£400,000, reduced to £320,000 for early payment).

## Root Cause

The SQL injection vulnerability existed in **three legacy webpages** operated by TalkTalk following its acquisition of Tiscali UK in 2009. According to the ICO investigation:

- TalkTalk **failed to remove or secure** the legacy webpages that enabled attackers to access the underlying database
- The **database software was outdated** — it was affected by a bug for which a fix had been available for **over 3.5 years** but had **not been applied**
- The database bug enabled attackers to **bypass access restrictions** that were in place
- TalkTalk **failed to conduct appropriate proactive monitoring** to discover vulnerabilities

## The Attack Timeline

- **17 July 2015:** First SQL injection attack on the vulnerable pages (not detected)
- **2-3 September 2015:** Second SQL injection attack (not detected due to lack of monitoring)
- **15-21 October 2015:** Main attack — vulnerabilities in three webpages exploited via SQL injection
- **21 October 2015:** TalkTalk becomes aware of the attack when their network slows down. Attack type identified around midday. Websites taken down about an hour later
- **22 October 2015:** TalkTalk reports the breach to the ICO and begins notifying the public

## Data Exposed

- 156,959 customers: names, addresses, dates of birth, phone numbers, email addresses
- 15,656 customers: bank account numbers and sort codes
- Potential for identity theft and financial fraud

## The Perpetrators

The breach was the work of **several individuals**, not a lone teenager. Those convicted included:

- **Matthew Hanley** — accessed the TalkTalk database and extracted the stolen data, then passed a file of ~8,000 customers' details to Connor Allsopp. Jailed for 12 months (Nov 2018).
- **Connor Allsopp** — supplied the stolen data onward for fraud. Jailed for 8 months (Nov 2018).
- **Elliott Gunton** — used the automated **sqlmap** tool to probe TalkTalk's webpages and identify the SQL injection vulnerabilities; later convicted (2019) on computer-misuse and money-laundering charges.

A 15-year-old from Northern Ireland was also among those investigated and convicted, but he was **not the sole perpetrator** — the attack involved multiple, older offenders. This still underscores how accessible SQL injection tooling (like sqlmap) has become — modest resources are enough to exploit such vulnerabilities.

## Aftermath

- **ICO fine:** £400,000 (largest ever at that time; reduced to £320,000)
- **House of Commons inquiry** into the breach
- **Share price drop:** TalkTalk lost approximately 12% of its market value
- **Customer exodus:** Thousands of customers left the service
- **Reputational damage:** Years of brand damage and loss of customer trust

## Key Takeaways for Developers

1. **SQL injection is still #1 on the OWASP Top 10 for a reason** — it was well-understood for over a decade before this breach and still caused massive damage.
2. **Legacy code is a ticking time bomb.** Pages acquired through mergers and acquisitions must be audited, secured, or decommissioned. TalkTalk inherited these pages 6 years before the attack.
3. **Patch your database.** A critical database bug had been fixed for 3.5 years but the patch was never applied.
4. **Monitor for attacks.** Two prior SQL injection attempts went completely unnoticed due to lack of monitoring.
5. **Use parameterized queries.** SQL injection has been preventable since the early 2000s with parameterized queries / prepared statements.

## References

- [ICO - TalkTalk cyber attack investigation](https://ico.org.uk/about-the-ico/media-centre/talktalk-cyber-attack-how-the-ico-investigation-unfolded/)
- [Wikipedia - 2015 TalkTalk data breach](https://en.wikipedia.org/wiki/2015_TalkTalk_data_breach)
- [The Guardian - TalkTalk customer data at risk](https://www.theguardian.com/business/2015/oct/22/talktalk-customer-data-hackers-website-credit-card-details-attack)
- [Open University - Case study: the TalkTalk hack](https://www.open.edu/openlearn/digital-computing/learning-major-cyber-security-incidents/content-section-3)
