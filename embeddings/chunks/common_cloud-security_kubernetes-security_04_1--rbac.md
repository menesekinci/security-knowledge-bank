---
source: "common/cloud-security/kubernetes-security.md"
title: "Kubernetes Security"
heading: "1. RBAC"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, network, overview, policies, rbac, security, table]
chunk: 4/10
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