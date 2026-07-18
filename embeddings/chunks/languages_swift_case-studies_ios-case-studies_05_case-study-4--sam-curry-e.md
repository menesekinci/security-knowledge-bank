---
source: "languages/swift/case-studies/ios-case-studies.md"
title: "iOS / Swift Case Studies"
heading: "Case Study 4: Sam Curry et al. — Apple Bug Bounty Mass Hunt (55 Vulnerabilities)"
category: "case-study"
language: "swift"
severity: "critical"
tags: [case, case-study, references, study, swift]
chunk: 5/6
---

## Case Study 4: Sam Curry et al. — Apple Bug Bounty Mass Hunt (55 Vulnerabilities)

### Incident Overview
- **Date**: July – October 2020
- **Team**: Sam Curry, Brett Buerhaus, Ben Sadeghipour, Samuel Erb, Tanner Barnes
- **Results**: 55 vulnerabilities (11 Critical, 29 High, 13 Medium, 2 Low)

### Description
A team of five security researchers spent 3 months hacking Apple's infrastructure. They discovered vulnerabilities that could allow a worm capable of automatically taking over any victim's iCloud account, retrieving source code for internal Apple projects, and compromising Apple's industrial control warehouse software.

### Key Findings
1. **iCloud Worm**: Cross-site scripting in Apple's customer support portal could be used to steal iCloud session tokens and propagate automatically between victims
2. **Internal Source Code Access**: Flaw in Apple's Fastly CDN configuration exposed internal `.git` directories
3. **Employee Session Takeover**: Admin panel authentication bypass via HTTP request smuggling
4. **Warehouse Control Software**: Industrial control software used by Apple for their warehouses was internet-accessible with default credentials

### Impact
- Complete compromise of Apple customer and employee accounts
- Access to Apple source code repositories
- Physical infrastructure control (warehouse operations)
- All vulnerabilities were patched within 1-2 business days

### Lessons for iOS/macOS Developers
1. HTTP request smuggling is still relevant — use proper HTTP/2 or disable HTTP/1.1 downgrade
2. CDN misconfigurations expose backends — use `X-Forwarded-For` validation
3. Default credentials on any service are unacceptable
4. Session tokens must be HttpOnly + Secure + SameSite

### Sources
- https://samcurry.net/hacking-apple
- https://support.apple.com/en-us/HT201536

---