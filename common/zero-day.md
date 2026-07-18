# Zero-Day Vulnerabilities (0-day) and Patch Lag (n-day)

> **Severity:** Critical (when weaponized against exposed assets)  
> **CWE:** Context-dependent (CWE-1395 Dependency on Vulnerable Third-Party Component; CWE-1035 2017 OWASP Top 10 A9; specific flaw CWEs vary — e.g. CWE-502, CWE-20, CWE-787)  
> **AI Generation Risk:** High — models trained on pre-disclosure code patterns, outdated dependency examples, and “copy this CVE fix” snippets that miss complete mitigations; AI may regenerate vulnerable patterns after public n-day disclosure

---

## Vulnerability Explanation

### Definitions

| Term | Meaning |
|------|---------|
| **0-day (zero-day)** | A vulnerability that is actively exploitable **before** the vendor has released a patch (or before defenders know to mitigate). Attackers and sometimes vendors may know; general defenders do not have a fix available. |
| **n-day** | A vulnerability that is **public and/or patched**, but many systems remain unpatched for *n* days (or weeks/months). Exploitation of n-days is often more common than true 0-days because exploit code and scanners proliferate after disclosure. |
| **Patch lag** | The operational delay between patch availability and widespread deployment: change freezes, regression testing, embedded/IoT update friction, “it still works” risk aversion. |
| **1-day** | Informal: immediately after patch/advisory, reverse engineers diff the patch and produce exploits quickly. |

Zero-days are not a single CWE — they are a **lifecycle state** of a vulnerability. The same bug is a 0-day before disclosure/patch, then becomes an n-day risk for anyone who does not update.

### Why 0-days and n-days matter differently

- **0-day:** Limited to sophisticated actors or silent black markets; detection relies on anomaly/behavior, not signature matching of known CVE IDs.
- **n-day:** Mass exploitation is routine. Public PoCs, Metasploit modules, and automated scanners appear within hours to days. Internet-wide scanning finds unpatched services at scale.
- **Patch lag multiplies blast radius:** Even “patched in library X” means nothing until every downstream container image, appliance firmware, and internal service is rebuilt and redeployed.

### AI-specific risk: outdated training data

Large language models and coding agents:

1. **Memorize vulnerable code** from GitHub snapshots that predate fixes.
2. **Recommend dependency versions** that were current at training time but are now known-bad.
3. **“Fix” incomplete patches** — apply a surface check while missing a deeper variant (common after incomplete CVE advisories).
4. **Cannot know tomorrow’s 0-day** — but they **can** reintroduce yesterday’s n-day if the secure pattern is rarer in training data than the vulnerable one.
5. **Hallucinate CVE mitigations** or invent non-existent safe APIs, leaving systems worse than before.

Treating AI output as “modern best practice” without SCA (software composition analysis), CVE feeds, and human review is itself a security control failure.

**This document intentionally contains no exploit proof-of-concept code.** Focus is classification, operations, and AI-era engineering risk.

---

## How AI / Vibe Coding Generates This

Vibe coding increases **n-day exposure** and can accidentally reintroduce **known** vulnerable patterns:

- Scaffolding with `npm create` / `pip install` of packages pinned to old majors from blog posts.
- AI copies Log4j-era Java logging or JNDI usage from old Stack Overflow answers still in the corpus.
- Generated Dockerfiles based on `ubuntu:latest` or unpinned base images that lag behind security updates.
- “Upgrade later” comments left in AI-generated TODOs that never become tickets.
- Agents that “solve the error” by **downgrading** a package to an older version that compiles — often reintroducing fixed CVEs.
- Auto-generated SBOM-less monorepos where transitive deps are invisible to developers.
- Security “fixes” that only rename variables or add comments claiming a CVE is addressed.
- Using AI to write WAF rules or detections from incomplete public writeups, creating a false sense of safety while the root package remains vulnerable.

For true 0-days, AI does not “create” vendor 0-days, but AI-assisted development can:

- Increase attack surface (more code, more deps, more exposed endpoints) faster than security review scales.
- Normalize insecure defaults that become the next class of 0-day hunting ground (e.g. novel deserialization sinks, new template engines).

---

## Vulnerable Code Example (realistic)

Illustrative **n-day / patch-lag patterns** (not exploit PoCs) — patterns AI frequently emits:

### 1) Pinned known-vulnerable dependency (conceptual)

```xml
<!-- pom.xml — AI regenerated from an old tutorial -->
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <!-- 🔴 Version known-vulnerable during Log4Shell era; still appears in stale examples -->
  <version>2.14.1</version>
</dependency>
```

### 2) “It works” suppression of SCA

```yaml
# .github/workflows/ci.yml — AI "fixed" failing pipeline
- name: Audit
  run: npm audit
  continue-on-error: true   # 🔴 n-day CVEs never block merge
```

### 3) Unpinned base image + no rebuild policy

```dockerfile
FROM node:16   # 🔴 EOL base; AI defaults from old docs
COPY . .
RUN npm install   # no npm ci, no lockfile verification
CMD ["node", "server.js"]
```

### 4) Incomplete “mitigation” comment without actual upgrade

```java
// "Mitigated Log4Shell by not logging user input"  — 🔴 incomplete; JNDI still reachable via other paths
log.info("User action");
```

These examples show **process and supply-chain** failures that keep n-day risk alive; they are not attack recipes.

---

## Secure Code Fix

### Operational controls (primary defense against 0/n-day)

```yaml
# Example policy fragment — block known-bad, force rebuild cadence
dependency-policy:
  fail_ci_on: ["critical", "high"]
  allow_severity: false          # require ticket + expiry for any exception
  max_patch_age_hours: 72       # SLO: critical internet-facing within 72h
  sca_tools: ["osv-scanner", "dependabot", "snyk"]  # pick your stack
  container:
    base_image_refresh: weekly
    recreate_on_cve: true
```

### Engineering practices

1. **SBOM + continuous SCA** on every build (Syft/Grype, OSV-Scanner, vendor SCA).
2. **Pin and regenerate** lockfiles; renovate/dependabot with auto-merge for safe patches after tests.
3. **Emergency patch runbooks** — pre-approved change windows for Critical RCEs; feature flags to disable vulnerable sinks.
4. **Defense in depth** while waiting for patches: WAF virtual patches, network segmentation, disable unused protocols/features (e.g. remove dangerous lookups, close admin ports).
5. **Attack surface reduction** — fewer public services mean fewer places an n-day scanner scores a hit.
6. **AI hygiene:**  
   - Re-run SCA after every AI-assisted dependency change.  
   - Prefer official migration guides over model-suggested version numbers.  
   - Maintain an internal “banned APIs / banned versions” list in linters.  
   - Never silence `npm audit` / `pip-audit` / `cargo audit` in CI for production paths.

### Detection for unknown 0-days (no CVE yet)

- EDR/XDR behavioral detections, memory integrity, unusual child processes.
- Canary tokens, honeypot endpoints, strict egress allowlists.
- Anomaly detection on auth, deserialization, and template rendering paths.
- Bug bounty and continuous red team for your actual stack — not only CVE chasing.

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

## Real-World CVEs / References

### Log4Shell — n-day mass exploitation after disclosure

- **[CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)** — Apache Log4j2 JNDI injection (Log4Shell). Once public, global scanning and mass exploitation demonstrated classic **patch lag**: many organizations needed days to weeks to inventory transitive Java dependencies and redeploy. Follow-on issues ([CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046), [CVE-2021-45105](https://nvd.nist.gov/vuln/detail/CVE-2021-45105)) showed incomplete first patches and the cost of partial mitigations.

### MOVEit — mass exploitation of a high-impact file-transfer flaw

- **[CVE-2023-34362](https://nvd.nist.gov/vuln/detail/CVE-2023-34362)** — Progress MOVEit Transfer SQL injection leading to widespread data theft campaigns. Illustrates how a single product 0-day/n-day cycle becomes **supply-chain-like impact** for hundreds of organizations depending on one appliance/vendor update pipeline.

### Memory-safety n-days that defined industry response

- **[CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)** — Heartbleed (OpenSSL): long patch lag across appliances and forgotten OpenSSL embeds.
- **[CVE-2015-0235](https://nvd.nist.gov/vuln/detail/CVE-2015-0235)** — GHOST (glibc `gethostbyname`): libc-level n-day requiring full host rebuilds.
- **[CVE-2015-7547](https://nvd.nist.gov/vuln/detail/CVE-2015-7547)** — glibc `getaddrinfo` stack-based buffer overflow: again, OS/vendor lag.
- **[CVE-2021-3156](https://nvd.nist.gov/vuln/detail/CVE-2021-3156)** — Baron Samedit (sudo heap overflow): privilege escalation n-day on countless Linux fleets.

### Standards and catalogs

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — prioritize actively exploited n-days  
- [OWASP Dependency-Check / SCA guidance](https://owasp.org/www-community/Component_Analysis)  
- [NVD](https://nvd.nist.gov/) / [OSV](https://osv.dev/) for version-level vulnerability data  

---

## Vibe-Coding Red Flags

| Red flag | Risk |
|----------|------|
| AI pins packages from a 2019 blog post | Instant n-day debt |
| CI green with `continue-on-error: true` on audit | Policy theater |
| “We’ll upgrade Log4j later” in generated TODO | Classic lag pattern |
| Model invents a CVE number or fake patched version | False confidence |
| Downgrade dependency to fix build errors | Often reintroduces fixed CVEs |
| No SBOM in release artifacts | Cannot answer “are we affected?” in 1 hour |
| Only reading Twitter PoCs, not applying vendor patches | Wrong control plane |
| Assuming WAF alone “fixed Log4Shell” | Incomplete mitigation history repeated |
| AI claims code is safe because “modern framework” | Frameworks still pull vulnerable transitive deps |
| Copying exploit snippets into test suites in prod CI | Dangerous and unnecessary for verification |

**Bottom line:** Zero-days are a **time dimension** of risk. Most catastrophic internet incidents that “felt like zero-days” to victims were **n-days with brutal patch lag**. AI accelerates code and dependency sprawl; pair every AI coding workflow with SCA, patch SLOs, and ruthless inventory — and never ask models for exploit PoCs when the goal is defense.

---

*KB level: L1 common · Topic: 0-day vs n-day · No exploit PoCs · Pair with: supply-chain.md, secure-cicd.md, incident-response.md*
