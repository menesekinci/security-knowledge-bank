---
source: "common/zero-day.md"
title: "Zero-Day Vulnerabilities (0-day) and Patch Lag (n-day)"
heading: "Secure Code Fix"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 5/8
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