---
source: "languages/java/case-studies/equifax-breach-apache-struts.md"
title: "Equifax Data Breach: Apache Struts CVE-2017-5638"
category: "case-study"
language: "java"
severity: "critical"
tags: [case-study, details, impact, java, lesson, summary, technical, timeline]
---

# Equifax Data Breach: Apache Struts CVE-2017-5638

**Date:** March–September 2017  
**Severity:** Critical (CVSS 10.0)  
**CVE:** CVE-2017-5638  
**Impact:** 143 million customer records exposed

## Summary

The Equifax data breach is one of the **largest and most infamous data breaches in history**, directly caused by a failure to patch a known vulnerability in Apache Struts, a popular Java MVC web framework. The breach exposed highly sensitive data — Social Security numbers, birthdates, addresses, and credit card information — of 143 million US consumers, roughly **half the US population**.

## Timeline

| Date | Event |
|------|-------|
| **March 10, 2017** | CVE-2017-5638 published — RCE in Apache Struts Jakarta Multipart parser |
| **March 2017** | Patch released; Equifax fails to apply it |
| **May 13 – July 30, 2017** | Attackers exploit unpatched Struts vulnerability, exfiltrating data over 10 weeks |
| **July 29, 2017** | Equifax security team discovers suspicious network traffic |
| **September 7, 2017** | Equifax publicly discloses the breach |

## Technical Details

### The Vulnerability
CVE-2017-5638 (CVSS 10.0) is a **Remote Code Execution (RCE)** vulnerability in Apache Struts 2's Jakarta Multipart parser. The flaw: invalid `Content-Type` headers were processed as **OGNL (Object-Graph Navigation Language) code** instead of plain text. Attackers could send a crafted HTTP request with a malicious Content-Type header that the Struts parser would evaluate as executable OGNL expressions, allowing arbitrary code execution on the server.

```http
POST / HTTP/1.1
Content-Type: %{(#_='multipart/form-data')...
  (#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...
  (#cmd="cat /etc/passwd")...
```

### Why It Worked
- OGNL is a powerful expression language that can **create objects, call methods, and access Java reflection**
- The Struts parser didn't sanitize or validate the Content-Type header before evaluating it
- The vulnerability was **trivially exploitable** — public exploit code was available within hours

### Why Equifax Was Vulnerable
Equifax had **two months** between the patch release and the start of the breach to update their systems. Internal processes failed due to:
- Lack of visibility into which systems used Struts
- Manual patch deployment requiring rebuilding and testing each application
- No automated vulnerability scanning in their CI/CD pipeline
- The Struts patch was "labor intensive and difficult" per Ars Technica

## Impact

- **143 million** Social Security numbers exposed
- **209,000** credit card numbers stolen in one batch
- CEO, CIO, and CSO were all **terminated**
- Equifax paid at least **$1.38 billion** in breach-related costs (fines, settlements, security improvements)
- Congressional hearings and new data breach legislation proposed
- **$700 million** settlement with FTC, CFPB, and 50 US states/territories

## Key Lesson

The Equifax breach is a textbook case of **failure of basic security hygiene**. The most critical lesson: **patching known vulnerabilities matters more than anything else**. Apache Struts is used by ~65% of Fortune 100 companies — being popular doesn't make you immune; it makes you a target. Companies must:

1. **Inventory all software dependencies** — you can't patch what you don't know you have
2. **Automate vulnerability scanning** — manual processes fail for critical updates
3. **Treat all RCE vulnerabilities as immediate priority** — a CVSS 10.0 must be patched in hours, not months
4. **Implement defense in depth** — even if one layer is missed, another should catch it

## References

- https://avatao.com/deep-dive-into-the-equifax-breach-and-a-struts-vulnerability/
- https://www.blackduck.com/blog/equifax-apache-struts-vulnerability-cve-2017-5638.html
- https://archive.epic.org/privacy/data-breach/equifax/
- https://www.huntress.com/threat-library/data-breach/equifax-data-breach
- https://arstechnica.com/information-technology/2017/09/massive-equifax-breach-caused-by-failure-to-patch-two-month-old-bug/
