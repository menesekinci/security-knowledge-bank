---
source: "common/cloud-security/kubernetes-security.md"
title: "Kubernetes Security"
heading: "5. Secret Management"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, network, overview, policies, rbac, security, table]
chunk: 8/10
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