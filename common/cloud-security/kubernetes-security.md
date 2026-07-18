# Kubernetes Security

> **Category:** Common / Cloud Security
> **Last Updated:** July 2026

## Overview

Kubernetes is the dominant container orchestration platform, but its complexity creates a large attack surface. This document covers RBAC, Pod Security Standards, network policies, seccomp profiles, secret management, and CVE-backed examples of Kubernetes-specific vulnerabilities.

---

## Table of Contents

1. [RBAC (Role-Based Access Control)](#1-rbac)
2. [Pod Security Standards](#2-pod-security-standards)
3. [Network Policies](#3-network-policies)
4. [Seccomp & Security Contexts](#4-seccomp--security-contexts)
5. [Secret Management](#5-secret-management)
6. [CVEs & Real-World Examples](#6-cves--real-world-examples)

---

## 1. RBAC

RBAC misconfiguration is the #1 Kubernetes security issue. Overly permissive roles and wildcard bindings are common.

### Vulnerable RBAC (Cluster Admin for All)

```yaml
# VULNERABLE: Binding cluster-admin to all service accounts
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-bind-all
subjects:
  - kind: Group
    name: system:serviceaccounts  # ALL service accounts!
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin  # Full cluster admin!
  apiGroup: rbac.authorization.k8s.io
```

### Secure RBAC (Least Privilege)

```yaml
# SECURE: Minimal RBAC for a deployment automation service account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: deploy-bot
  namespace: app
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app
  name: deployer
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "update", "patch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]  # Only read specific secrets
    resourceNames: ["deploy-secret"]  # Bound to specific secret
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: app
  name: deploy-bot-binding
subjects:
  - kind: ServiceAccount
    name: deploy-bot
    namespace: app
roleRef:
  kind: Role
  name: deployer
  apiGroup: rbac.authorization.k8s.io
```

### Audit for Overly Permissive RBAC

```bash
# Check for wildcard verbs
kubectl get clusterroles --all-namespaces -o json | \
  jq '.items[] | select(.rules[].verbs[]? == "*") | .metadata.name'

# Check for cluster-admin bindings
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name == "cluster-admin") | .subjects'
```

---

## 2. Pod Security Standards

Pod Security Standards (PSS) define three levels: **Privileged**, **Baseline**, and **Restricted**. Pod Security Admission (PSA) enforces these since Kubernetes 1.23 (GA in 1.25).

### Vulnerable Pod (No Security Context)

```yaml
# VULNERABLE: Pod running as root with no restrictions
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
    - name: app
      image: my-app:latest
      # No securityContext — runs as root, can privilege escalate
```

### Secure Pod (Restricted PSS)

```yaml
# SECURE: Pod meeting PID=restricted PSS
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  labels:
    pod-security.kubernetes.io/enforce: restricted
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    runAsGroup: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: my-app:latest
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
        readOnlyRootFilesystem: true
        privileged: false
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
```

### Enforce PSS at Namespace Level

```yaml
# Enforce "restricted" PSS for critical namespaces
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

---

## 3. Network Policies

Network policies control pod-to-pod communication. Without them, all pods can communicate freely — this is the default.

### Vulnerable (No Network Policy)

```bash
# By default, Kubernetes allows ALL pod-to-pod traffic
# A compromised pod can reach any other pod in the cluster
kubectl run attacker --image=alpine -- sleep 3600
# Attacker can reach the database directly!
kubectl exec attacker -- wget http://database-service:5432
```

### Secure Network Policies

```yaml
# SECURE: Default deny ingress and egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
# SECURE: Allow frontend -> backend communication only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - port: 8080
          protocol: TCP
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - port: 5432
          protocol: TCP
```

---

## 4. Seccomp & Security Contexts

Seccomp filters restrict the system calls a container can make. Without it, containers can use hundreds of unnecessary syscalls.

### Secure Pod with Seccomp

```yaml
# SECURE: Pod with seccomp profile and security context
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault  # Use the runtime's default seccomp profile
  containers:
    - name: app
      image: nginx:alpine
      securityContext:
        seccompProfile:
          type: Localhost
          localhostProfile: profiles/audit.json  # Custom profile
```

### Custom Seccomp Profile (audit.json)

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["accept4", "bind", "close", "connect", "epoll_wait",
                "fstat", "getpeername", "getsockname", "listen",
                "mmap", "openat", "read", "recvfrom", "sendto",
                "write"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

---

## 5. Secret Management

Kubernetes Secrets are base64-encoded (not encrypted) by default. ETCD encryption at rest must be explicitly configured.

### Vulnerable Secret Pattern

```yaml
# VULNERABLE: Secret stored as plaintext in YAML committed to git
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
data:
  # base64 is NOT encryption!
  username: cm9vdA==              # root
  password: UGEkJHcwcmQhMTIz     # Pa$$word!123
---
# VULNERABLE: Using secrets in environment variables
apiVersion: v1
kind: Pod
spec:
  containers:
    - env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
      # Environment variables are visible via kubectl exec and in /proc
```

### Secure Secret Management

```yaml
# SECURE: Use external secrets operator with rotation
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h  # Auto-rotate
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: db-credentials
  data:
    - secretKey: username
      remoteRef:
        key: /production/database/username
    - secretKey: password
      remoteRef:
        key: /production/database/password
---
# SECURE: Mount secrets as files, not environment variables
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      volumeMounts:
        - name: secrets
          mountPath: /etc/secrets
          readOnly: true
  volumes:
    - name: secrets
      secret:
        secretName: app-secrets
```

### Enable ETCD Encryption at Rest

```yaml
# EncryptionConfiguration to enable AES-GCM encryption for secrets
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-256-bit-key>
      - identity: {}  # Fallback (should be last)
```

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

## References

- [Kubernetes Official CVE Feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [Aikido — Kubernetes Security Vulnerabilities Top Risks](https://www.aikido.dev/blog/kubernetes-security-vulnerabilities)
- [Palo Alto Networks — Modern Kubernetes Threats](https://unit42.paloaltonetworks.com/modern-kubernetes-threats/)
- [Wiz — IngressNightmare (CVE-2025-1974)](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities)
- [Datadog — The IngressNightmare Vulnerabilities](https://securitylabs.datadoghq.com/articles/ingress-nightmare-vulnerabilities-overview-and-remediation/)
- [Fortinet — IngressNightmare Analysis](https://www.fortinet.com/blog/threat-research/ingressnightmare-understanding-cve-2025-1974-in-kubernetes-ingress-nginx)
