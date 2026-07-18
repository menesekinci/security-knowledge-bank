---
source: "common/cloud-security/docker-security.md"
title: "Docker Security"
heading: "6. CVEs & Real-World Examples"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, containers, contexts, host, mounts, overview, privileged, security, table]
chunk: 9/11
---

## 6. CVEs & Real-World Examples

### CVE-2025-23266 — NVIDIA Container Toolkit Escape (NVIDIAScape)
- **Description**: Critical container escape vulnerability (CVSS 9.0) in NVIDIA Container Toolkit. Attackers with GPU access could escape the container and get code execution on the host. This was a systemic risk to AI infrastructure running GPU-accelerated containers
- **Affected**: NVIDIA Container Toolkit <= 1.17.7 (and GPU Operator <= 25.3.0)
- **CVSS**: 9.0 (Critical) — CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (CWE-426)
- **Fix**: Upgrade NVIDIA Container Toolkit to >= 1.17.8
- **Source**: https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape

### CVE-2025-9074 — Docker Desktop Container Escape
- **Description**: Vulnerability in Docker Desktop (<= 4.44.3) allowing a local Linux container to reach the Docker Engine API over the configured Docker subnet (`192.168.65.7:2375` by default, with or without Enhanced Container Isolation), enabling container escape on Windows and macOS
- **Affected**: Docker Desktop < 4.44.3 on Windows and macOS
- **CVSS**: 9.3 (Critical) — CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (CWE-668)
- **Fix**: Upgrade to Docker Desktop >= 4.44.3
- **PoC**: https://github.com/PtechAmanja/CVE-2025-9074-Docker-Desktop-Container-Escape
- **Source**: https://nvd.nist.gov/vuln/detail/cve-2025-9074

### runc Container Escape (November 2025 — Multiple CVEs)
- **Description**: Three high-severity vulnerabilities disclosed in runc (the container runtime used by Docker). The most critical involved "masked path" abuse — attackers could write to host filesystem paths that should have been hidden by the runtime. This allowed full container breakouts
- **Affected**: runc <= 1.1.x
- **CVSS**: 8.6 (High)
- **Fix**: Upgrade to runc >= 1.2.0
- **Source**: https://www.sysdig.com/blog/runc-container-escape-vulnerabilities/

### "Leaky Vessels" Vulnerabilities (2024)
- **Description**: Multiple container escape vulnerabilities discovered by Palo Alto Networks affecting Docker and runc. Flaws allowed attackers to escape containers through filesystem operations and runtime misconfigurations
- **Affected**: Docker Engine, runc
- **CVSS**: 8.6 (High)
- **Fix**: Update to latest Docker Engine and runc versions
- **Source**: https://www.paloaltonetworks.com/blog/cloud-security/leaky-vessels-vulnerabilities-container-escape/

### CVE-2025-23266 (Continued) — AI/ML Infrastructure Risk
- **Description**: Beyond the container escape, this vulnerability specifically threatens AI infrastructure where GPU-sharing is common. Attackers with container access could read GPU memory from other tenants
- **Remediation**:
  - Scan all container images for vulnerable NVIDIA Container Toolkit versions
  - Use pod security standards that restrict `hostPID` and `hostNetwork`
  - Consider hypervisor-based isolation for multi-tenant GPU workloads
- **Source**: https://www.upwind.io/feed/understanding-the-nvidiascape-cve-2025-23266-container-toolkit-vulnerability

### Docker Image Supply Chain (2022-ongoing)
- **Description**: Thousands of malicious images on Docker Hub exfiltrate credentials, mine cryptocurrency, and deploy backdoors. Official images (e.g., official Docker Hub images) are safer but still may contain vulnerable packages
- **Fix**: Use only trusted base images; pin image digests; scan with Trivy/Snyk; enforce image signing with Docker Content Trust
- **Source**: https://docs.docker.com/security/security-announcements/

---