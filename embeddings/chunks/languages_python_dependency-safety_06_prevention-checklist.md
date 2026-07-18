---
source: "languages/python/dependency-safety.md"
title: "Dependency Safety — Python Supply Chain"
heading: "Prevention Checklist"
category: "language-vuln"
language: "python"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] PIN every dependency to an exact version (`==`) — no ranges (`>=`, `~=`, `*`)
- [ ] VerifY hash integrity with `--require-hashes` or `hashin`
- [ ] Run `pip-audit` or `safety` in CI to detect known CVEs
- [ ] Use `pip freeze` or `pip-compile` (pip-tools) for deterministic builds
- [ ] Never install packages at runtime in production
- [ ] Review AI-generated package names for typos (e.g., `requeests` vs `requests`)
- [ ] Use private package indexes for internal packages with fallback controls
- [ ] Scan transitive dependencies (use `pipdeptree` to visualize)
- [ ] Enable Dependabot/Renovate for automatic security updates with review
- [ ] Use `pip install --no-deps` and install dependencies explicitly
- [ ] Set `PIP_REQUIRE_VIRTUALENV=true` to prevent system-wide installs
- [ ] Monitor PyPI for typo-squatted versions of your popular packages

---