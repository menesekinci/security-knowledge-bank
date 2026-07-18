---
source: "common/cloud-security/kubernetes-security.md"
title: "Kubernetes Security"
heading: "3. Network Policies"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, network, overview, policies, rbac, security, table]
chunk: 6/10
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