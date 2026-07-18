---
source: "common/cloud-security/ai-container-security.md"
title: "AI-Generated Container & Kubernetes Security"
heading: "4. Secure Code Fix"
category: "cloud-security"
language: "common"
severity: "critical"
tags: [cloud-security, code, explanation, overview, table, vulnerability, vulnerable]
chunk: 7/11
---

## 4. Secure Code Fix

### Secure Dockerfile (AI-Corrected)

```dockerfile
# SECURE: Multi-stage build with non-root user, pinned base, no secrets
# syntax=docker/dockerfile:1
FROM node:20-alpine@sha256:abc123... AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm audit --audit-level=high
COPY --chown=node:node src/ ./src/

FROM node:20-alpine@sha256:def456...
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --chown=appuser:appgroup --from=builder /app /app

# Drop all capabilities at runtime
USER appuser
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
```

**Key security improvements:**
- Pinned base image with SHA256 digest
- Multi-stage build — builder dependencies not in final image
- `COPY --chown` — files owned by non-root user
- `npm ci` instead of `npm install` — deterministic install
- `npm audit` — fail build on high-severity vulnerabilities
- `adduser` + `USER appuser` — non-root runtime
- `HEALTHCHECK` — enables orchestration-level failure detection
- No secrets in `ENV` — injected at runtime via secrets manager
- `.dockerignore` (not shown) — excludes `.env`, `.git`, `node_modules`

### Secure Kubernetes Manifest (AI-Corrected)

```yaml
# SECURE: Kubernetes manifest with Pod Security Standards, network policies, and secrets management
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
spec:
  replicas: 2
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      serviceAccountName: myapp-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 1001
        fsGroup: 1001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: myapp
          image: myapp@sha256:def456...
          ports:
            - containerPort: 3000
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true
            privileged: false
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: db-credentials
                  key: url
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /ready
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 10
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: secrets
              mountPath: /etc/secrets
              readOnly: true
      volumes:
        - name: tmp
          emptyDir: {}
        - name: secrets
          secret:
            secretName: app-secrets
---
# SECURE: Internal ClusterIP service (not NodePort)
apiVersion: v1
kind: Service
metadata:
  name: myapp
  namespace: production
spec:
  type: ClusterIP
  ports:
    - port: 3000
      targetPort: 3000
  selector:
    app: myapp
---
# SECURE: Default deny network policy
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
# SECURE: Allow ingress from ingress-gateway only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: myapp
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - port: 3000
---
# SECURE: Scoped RBAC — no cluster-admin
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: production
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: myapp-role
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
    resourceNames: ["app-secrets"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: production
  name: myapp-binding
subjects:
  - kind: ServiceAccount
    name: myapp-sa
    namespace: production
roleRef:
  kind: Role
  name: myapp-role
  apiGroup: rbac.authorization.k8s.io
```

---