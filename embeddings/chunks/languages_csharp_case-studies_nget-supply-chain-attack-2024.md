---
source: "languages/csharp/case-studies/nget-supply-chain-attack-2024.md"
title: "NuGet Supply Chain Attack: 60+ Malicious Packages Campaign (2024)"
category: "case-study"
language: "csharp"
severity: "high"
tags: [case-study, csharp, impact, incident, overview, specific, takeaways]
---

# NuGet Supply Chain Attack: 60+ Malicious Packages Campaign (2024)

**Language:** C# / .NET
**Vulnerability Type:** Supply Chain Attack (Typosquatting, Malicious Packages)
**Date:** July 2024 - Ongoing

## Overview

Throughout 2024, threat actors conducted an ongoing campaign of publishing malicious packages to the **NuGet** package manager, targeting .NET developers. The campaign began in August 2023 and escalated significantly in mid-2024, with security researchers uncovering **60+ new malicious packages** in a single disclosure. The packages used typosquatting, dependency confusion, and other techniques to trick developers into downloading malware that could compromise their development environments.

## How the Attack Worked

The malicious packages used several techniques:

1. **Typosquatting:** Package names mimicked popular legitimate packages (e.g., `MongoDB.Driver` vs. malicious variant).
2. **Dependency confusion:** Packages designed to be picked up by build systems looking for internal packages.
3. **Pre-install scripts:** Malicious code executed during package installation via NuGet's PowerShell install scripts.
4. **Runtime payload execution:** Some packages contained .NET code that executed during normal package usage.
5. **Artificial download counts:** Threat actors inflated download counts to make packages look popular and trustworthy.

The campaign demonstrated a sophisticated understanding of the NuGet ecosystem, including how to bypass automated security checks.

## Specific Incident: StripeApi.Net Typosquatting (Feb 2026)

In **February 2026**, ReversingLabs disclosed a malicious NuGet package called **StripeApi.Net** (uploaded Feb 16, 2026) that typosquatted the legitimate **Stripe.net** package (75M+ downloads). Key details:

- Mimicked the official Stripe.net package almost exactly (same icon, near-identical README, same tags)
- Package owner name was "StripePayments" — designed to look official
- Roughly **180,000 downloads** across **506 versions** (heavily inflated by the actor)
- Contained modified code that would **steal API tokens** during `StripeClient` initialization
- Designed to exfiltrate stolen data (API tokens + machine IDs) to a **Supabase** server (a legitimate backend-as-a-service, making detection harder)
- Target: Developer API keys for Stripe payment processing — a direct financial threat

**Caught early — limited real-world harm:** ReversingLabs reported the package shortly after it was published and NuGet removed it quickly. Investigators queried the attacker's own Supabase backend and found **no genuine stolen tokens — only a single test entry**, indicating the package was detected and removed before it could harvest real credentials.

## Impact

- Compromised developer workstations and CI/CD pipelines
- Theft of API keys, credentials, and sensitive data
- Potential introduction of backdoors into production applications
- For StripeApi.Net specifically: intended theft of payment processing API tokens (caught early — no real tokens were actually stolen)

## Key Takeaways for Developers

1. **Verify package identity:** Check the actual package owner, not just the display name. Look at the publisher's profile page.
2. **Check download patterns:** Legitimate packages grow downloads steadily over time. Sudden spikes or artificially uniform distribution across versions is suspicious.
3. **Audit dependencies regularly:** Use tools like dotnet list package --vulnerable and software composition analysis (SCA) tools.
4. **Pin to specific versions:** Use lock files (`packages.lock.json`) and avoid floating version ranges.
5. **Review install scripts:** Malicious code often hides in NuGet PowerShell install scripts — review them before running.
6. **Use package source mapping:** Configure NuGet to only restore from trusted package sources.

## References

- [The Hacker News - 60 New Malicious Packages Uncovered in NuGet](https://thehackernews.com/2024/07/60-new-malicious-packages-uncovered-in.html)
- [ReversingLabs - Malicious NuGet Package Targets Stripe](https://www.reversinglabs.com/blog/malicious-nuget-package-targets-stripe)
- [ReversingLabs - Inside the NuGet Hackers' Toolset](https://www.reversinglabs.com/blog/inside-the-nuget-hackers-toolset)
- [Microsoft - Building a Safer Future: How NuGet is Tackling Software Supply Chain Threats](https://devblogs.microsoft.com/dotnet/building-a-safer-future-how-nuget-is-tackling-software-supply-chain-threats/)
- [Industrial Cyber - Socket Researchers Uncover NuGet Packages That Sabotage PLCs](https://industrialcyber.co/control-device-security/socket-researchers-uncover-nuget-packages-that-silently-sabotage-industrial-plcs-safety-critical-systems/)
