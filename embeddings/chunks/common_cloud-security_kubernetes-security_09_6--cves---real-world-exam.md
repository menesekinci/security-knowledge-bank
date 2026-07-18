---
source: "common/cloud-security/kubernetes-security.md"
title: "Kubernetes Security"
heading: "6. CVEs & Real-World Examples"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, network, overview, policies, rbac, security, table]
chunk: 9/10
---

## 6. CVEs & Real-World Examples

### CVE-2024-10220 — Kubernetes gitRepo Volume Command Injection
- **Description**: Critical vulnerability in the deprecated gitRepo volume mechanism. An attacker with permission to create a pod using a gitRepo volume could execute arbitrary commands on the **host node** with root privileges. The gitRepo volume cloned a Git repository, and specially crafted hooks in the repo would run on the host
- **Affected**: kubelet through 1.28.11, 1.29.x through 1.29.6, 1.30.x through 1.30.2
- **CVSS**: 8.1 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (CWE-22)
- **Fix**: Upgrade kubelet; disable the gitRepo volume type
- **Source**: https://nvd.nist.gov/vuln/detail/cve-2024-10220

### CVE-2025-1974 — IngressNightmare (Ingress NGINX RCE)
- **Description**: Critical unauthenticated RCE vulnerability in the Ingress-NGINX admission controller (CVSS 9.8). Attackers could send a malicious AdmissionReview request to the webhook endpoint and execute arbitrary code on the ingress controller's pod. This could lead to cluster compromise because the ingress controller often has elevated permissions to read all Secrets in the cluster
- **Affected**: Ingress-NGINX controller
- **CVSS**: 9.8 (Critical)
- **Fix**: Upgrade ingress-nginx to the patched version; restrict network access to the admission webhook
- **Source**: https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities

### CVE-2024-7598 — Kubernetes Network Policy Bypass via Race Condition
- **Description**: A race condition in kube-apiserver during namespace termination. When a namespace was deleted, network policies were removed **before** pods, granting those pods a temporary window with unrestricted network access — bypassing all network restrictions
- **Affected**: Kubernetes clusters with NetworkPolicies in use
- **CVSS**: 3.1 (Low) — CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N (CWE-362 Race Condition)
- **Fix**: Fixed in Kubernetes 1.28.11, 1.29.6, 1.30.3, and 1.31.0
- **Source**: https://groups.google.com/g/kubernetes-security-announce/c/67D7UFqiPRc

### CVE-2025-0426 — Kubernetes Kubelet DoS
- **Description**: Denial of service vulnerability in kubelet allowing a malicious pod to exhaust kubelet resources, potentially impacting node stability
- **Affected**: Kubernetes kubelet (specific versions)
- **CVSS**: 6.2 (Medium)
- **Fix**: Apply node resource quotas and pod resource limits; upgrade kubelet
- **Source**: https://www.sentinelone.com/vulnerability-database/cve-2025-0426/

### CVE-2023-2431 — Kubelet Seccomp Profile Enforcement Bypass
- **Description**: A security issue in the kubelet allows pods to bypass seccomp profile enforcement. Pods that use the `localhost` type for their seccomp profile but specify an **empty** `localhostProfile` field run **unconfined** (seccomp disabled) instead of being rejected — silently removing syscall filtering the operator believed was in place
- **Affected**: kubelet v1.27.0–1.27.1, v1.26.0–1.26.4, v1.25.0–1.25.9, and ≤1.24.13
- **CVSS**: 5.5 (Medium) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N (CWE-1287)
- **Fix**: Upgrade to kubelet 1.27.2, 1.26.5, 1.25.10, or 1.24.14; audit pods for empty `localhostProfile` fields
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2023-2431

### CVE-2024-21626 — runc Container Escape ("Leaky Vessels")
- **Description**: An internal file-descriptor leak in runc (the default OCI runtime under most Kubernetes CRI implementations) lets an attacker cause a newly-spawned container process to have a working directory in the **host** filesystem namespace, enabling a full container-to-host escape. A malicious image or a crafted `WORKDIR` can trigger it — allowing a compromised pod to break out onto the node
- **Affected**: runc ≤ 1.1.11 (as bundled by container runtimes on affected nodes)
- **CVSS**: 8.6 (High) — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H (CWE-403 / CWE-668)
- **Fix**: Upgrade runc to ≥ 1.1.12 on all nodes; enforce restricted Pod Security Standards, read-only root filesystems, and dropped capabilities to limit blast radius
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2024-21626

---