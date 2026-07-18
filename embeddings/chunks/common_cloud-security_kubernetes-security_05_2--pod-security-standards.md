---
source: "common/cloud-security/kubernetes-security.md"
title: "Kubernetes Security"
heading: "2. Pod Security Standards"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, network, overview, policies, rbac, security, table]
chunk: 5/10
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