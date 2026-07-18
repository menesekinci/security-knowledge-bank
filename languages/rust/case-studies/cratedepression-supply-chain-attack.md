# CrateDepression: Rust Supply-Chain Attack Infecting Cloud CI Pipelines

**Date:** May 2022 (discovered by SentinelLabs)  
**Crate:** rustdecimal (typosquat of rust_decimal)  
**Type:** Software Supply Chain Attack

## Summary

The "CrateDepression" campaign was a supply-chain attack targeting the Rust development community. A malicious crate named `rustdecimal` (typosquatting the legitimate and popular `rust_decimal` crate) was published to crates.io. The attack specifically targeted GitLab CI pipelines, deploying second-stage Go-based malware via the Mythic framework to achieve persistent remote access.

## How It Worked

1. **Typosquatting**: The threat actor published `rustdecimal` (note: no underscore) to crates.io, impersonating the legitimate `rust_decimal` crate.

2. **Environment Targeting**: The malicious code checked environment variables to determine if it was running inside a GitLab CI pipeline.

3. **Multi-stage Payload**: Upon execution in a CI pipeline, the crate downloaded a second-stage payload — Go binaries built on the **Mythic** framework — enabling command-and-control (C2) communication.

4. **Persistence**: Once infected, the CI pipeline could be used for large-scale supply chain attacks, potentially compromising downstream software built by the targeted organization.

## Impact

- The Rust Security Response Working Group removed the malicious crate on **May 10, 2022**.
- Versions 1.22.0 through 1.23.5 were all compromised.
- The legitimate `rust_decimal` crate was **not** compromised — only the typosquatted name.
- Attackers could gain persistent access to cloud CI infrastructure, enabling further supply chain compromise.

## Key Lesson

Rust's package ecosystem (crates.io) is susceptible to the same typosquatting attacks as other language ecosystems. Always verify exact crate names, use `cargo audit` regularly, and audit dependencies for unexpected changes. CI/CD pipelines are a high-value target because compromising build infrastructure can lead to poisoning of downstream artifacts.

## IOCs

- C2: `api.kakn.li`
- Malicious versions: 1.22.0 through 1.23.5
- 15 malicious crate versions identified by SentinelLabs (versions 1.22.0 through 1.23.5)

## References

- https://rhisac.org/threat-intelligence/cratedepression-rust-supply-chain-attack/
- https://www.sentinelone.com/labs/cratedepression-rust-supply-chain-attack-infects-cloud-ci-pipelines-with-go-malware/
- https://blog.rust-lang.org/2022/05/10/malicious-crate-rustdecimal.html
- https://cycode.com/blog/security-advisory-cratedepression/
