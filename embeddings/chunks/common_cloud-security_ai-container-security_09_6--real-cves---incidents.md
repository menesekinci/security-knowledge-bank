---
source: "common/cloud-security/ai-container-security.md"
title: "AI-Generated Container & Kubernetes Security"
heading: "6. Real CVEs & Incidents"
category: "cloud-security"
language: "common"
severity: "critical"
tags: [cloud-security, code, explanation, overview, table, vulnerability, vulnerable]
chunk: 9/11
---

## 6. Real CVEs & Incidents

### CVE-2024-21626 — runc Container Escape ("Leaky Vessels")

- **Description**: Critical file descriptor leak in runc (the default container runtime used by Docker). An attacker could cause a newly-spawned container process to have a working directory in the host filesystem namespace, enabling full container escape. Three attack variants were documented, including overwriting host binaries for complete host compromise. This vulnerability was directly exploitable through malicious images — a supply chain risk amplified by AI-generated Dockerfiles that pull untrusted base images.
- **Affected**: runc <= 1.1.11
- **CVSS**: 8.6 (High) — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H
- **Fix**: Upgrade to runc >= 1.1.12
- **AI relevance**: AI-generated Dockerfiles frequently use unpinned base images (`FROM ubuntu:latest`) that can silently roll to vulnerable versions of runc. The "Leaky Vessels" class of vulnerabilities demonstrated that a malicious image could trigger the escape — exactly the supply chain scenario AI-generated builds are most exposed to.
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2024-21626

### CVE-2025-9074 — Docker Desktop Container Escape

- **Description**: Vulnerability in Docker Desktop (<= 4.44.3) allowing a local Linux container to reach the Docker Engine API over the configured Docker subnet (`192.168.65.7:2375` by default) — with or without Enhanced Container Isolation (ECI) enabled — enabling container escape and full host takeover. This affects developers running Docker Desktop for local AI-assisted development — a common workflow where vibe-coded apps are tested locally before deployment.
- **Affected**: Docker Desktop before 4.44.3 on Windows and macOS
- **CVSS**: 9.3 (Critical) — CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (CWE-668)
- **Fix**: Upgrade to Docker Desktop >= 4.44.3
- **AI relevance**: AI coding assistants generate `docker run -v /var/run/docker.sock:/var/run/docker.sock` patterns for local development, directly exposing the Docker socket — a pattern that becomes dangerous when combined with this vulnerability.
- **Source**: https://nvd.nist.gov/vuln/detail/cve-2025-9074

### CVE-2025-23266 — NVIDIA Container Toolkit Escape (NVIDIAScape)

- **Description**: Critical container escape vulnerability (CVSS 9.0) in NVIDIA Container Toolkit. Attackers with GPU access could escape containers and gain code execution on the host. This is a systemic risk for AI infrastructure running GPU-accelerated containers — the exact environment where AI training and inference workloads run.
- **Affected**: NVIDIA Container Toolkit <= 1.17.7 (and GPU Operator <= 25.3.0)
- **CVSS**: 9.0 (Critical) — CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (CWE-426)
- **Fix**: Upgrade NVIDIA Container Toolkit to >= 1.17.8
- **AI relevance**: AI/ML infrastructure is the primary deployment target for GPU containers. AI-generated Dockerfiles that pull NVIDIA CUDA base images without version pinning are at elevated risk.
- **Source**: https://nvd.nist.gov/vuln/detail/cve-2025-23266

### "Leaky Vessels" Vulnerabilities Cluster (2024)

- **Description**: Multiple container escape vulnerabilities (CVE-2024-21626 and related) discovered by Palo Alto Networks. Flaws allowed attackers to escape containers through filesystem operations and runtime misconfigurations. The vulnerabilities demonstrated that "quick start" Dockerfiles — of the type AI assistants produce — could be weaponized for host compromise.
- **Affected**: Docker Engine, runc
- **CVSS**: Up to 8.6 (High)
- **AI relevance**: AI-generated Dockerfiles frequently lack security hardening (no USER, no cap_drop, no seccomp) — the exact protections that mitigate these escape vectors.
- **Sources**:
  - https://www.paloaltonetworks.com/blog/cloud-security/leaky-vessels-vulnerabilities-container-escape/
  - https://orca.security/resources/blog/leaky-vessels-docker-container-vulnerabilities/

### Moltbook Breach — Vibe-Coded App Exposes 1.5 Million API Keys (January 2026)

- **Description**: The founder of Moltbook, an AI-agent social network, publicly stated he "vibe-coded" the entire platform without writing a single line of code. Wiz Research discovered a misconfigured Supabase database within minutes of investigation — the client-side JavaScript contained a Supabase API key granting full read/write access to the entire production database. **1.5 million API authentication tokens** and 35,000 email addresses were exposed. The database was publicly writable with no Row Level Security (RLS) configured.
- **Impact**: AI agent tokens, user emails, and private messages fully exposed. The platform also had no rate limiting — attackers registered millions of fake agents with a simple loop.
- **AI relevance**: Vibe-coded apps bypass traditional security review. The founder had no engineering team and no security review process. The vulnerability was a configuration gap that any experienced engineer would have caught in a standard code review.
- **Lessons**: API keys must never be exposed client-side; Row Level Security must be enforced at the database level; AI-generated applications require mandatory security review before production deployment.
- **Source**: https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys

### Docker Hub Secrets Exposure — 10,000+ Images Leaking Credentials (2025-2026)

- **Description**: Security researchers at Flare and RWTH Aachen found that over 10,000 public Docker Hub images contained leaked secrets — SSH private keys, API tokens, and database credentials embedded in image layers. **52,107 private keys** and **3,158 API secrets** were discovered. Many of these secrets originated from Dockerfiles where credentials were baked in via `ENV` or `COPY` commands — the same patterns AI assistants commonly generate.
- **Impact**: Cloud environments, CI/CD pipelines, and production databases exposed
- **AI relevance**: AI-generated Dockerfiles frequently include `ENV API_KEY=...` or `COPY .env .` — patterns that bake credentials into image layers, making them permanently visible via `docker history`.
- **Source**: https://www.darkreading.com/cloud-security/docker-leaks-api-secrets-private-keys-cybercriminals

### Cloud Security Alliance — AI-Generated Code Vulnerability Surge (2026)

- **Description**: The Cloud Security Alliance documented a 400% increase in cloud misconfiguration vulnerabilities traced to AI-generated code from 2024 to 2026. Key finding: **45% of AI-generated cloud configuration samples introduce OWASP Top 10 vulnerabilities** — a pass rate that has not improved across multiple testing cycles. Dockerfiles and Kubernetes manifests were the highest-risk categories.
- **Impact**: Systemic insecurity in infrastructure-as-code generated by AI
- **Fix**: AI-generated code must pass through security scanning (Trivy, Kube-bench, Checkov) before deployment
- **Source**: https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-generated-code-vulnerability-surge-2026/

---