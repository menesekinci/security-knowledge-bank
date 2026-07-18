---
source: "common/cloud-security/ai-container-security.md"
title: "AI-Generated Container & Kubernetes Security"
heading: "3. Vulnerable Code Examples"
category: "cloud-security"
language: "common"
severity: "critical"
tags: [cloud-security, code, explanation, overview, table, vulnerability, vulnerable]
chunk: 6/11
---

## 3. Vulnerable Code Examples

### Vulnerable AI-Generated Dockerfile

```dockerfile
# VULNERABLE: AI-generated Dockerfile with multiple security flaws
FROM ubuntu:latest                          # Unpinned base image — drifts

RUN apt-get update && apt-get install -y python3 python3-pip nodejs curl
                                            # No --no-install-recommends, bloated

WORKDIR /app
COPY . /app                                 # Copies everything (including secrets, .git)

RUN pip install -r requirements.txt         # No hash verification
RUN npm install -g serve                    # Global npm install — privilege escalation

ENV DATABASE_URL=postgresql://admin:password123@db:5432/myapp
ENV API_KEY=sk-test-abc123                  # Secrets baked into image layers!
ENV NODE_ENV=production

ADD https://example.com/archive.tar.gz /tmp/# ADD auto-extracts, potential zip-slip

EXPOSE 3000
EXPOSE 8080
EXPOSE 5432                                 # Over-exposed ports

USER root                                   # Runs as root (default, but explicit here)

CMD ["python", "app.py"]                    # No HEALTHCHECK
```

**Security flaws in this Dockerfile:**
- `FROM ubuntu:latest` — not pinned to a digest, image can change anytime
- `apt-get install` without `--no-install-recommends` — installs 100+ unnecessary packages (bloated attack surface)
- `COPY . /app` — copies `.env`, `.git`, `node_modules`, `secrets/` into the image
- `pip install` without `--require-hashes` — no supply chain verification
- `ENV` with database URL and API key — secrets visible in `docker history`
- `ADD` with archive URL — unnecessary, use `curl` + `COPY` instead
- `EXPOSE 5432` — no reason to expose database port from app container
- No `HEALTHCHECK` — container failure undetected

### Vulnerable AI-Generated Kubernetes Manifest

```yaml
# VULNERABLE: AI-generated Kubernetes manifest with multiple security flaws
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
        - name: myapp
          image: myapp:latest                     # Unpinned image tag
          ports:
            - containerPort: 3000
          env:
            - name: DATABASE_URL
              value: "postgresql://admin:pass@db:5432/myapp"
            - name: API_KEY
              value: "sk-xxxxxxxxxxxxxxxx"        # Hardcoded secrets!
          # No securityContext — runs as root
          # No resources.limits — can exhaust cluster
          # No livenessProbe / readinessProbe
          # No volume mounts
      # No serviceAccountName — uses default (over-permissioned)
      # No imagePullSecrets
      hostNetwork: true                           # Bypasses network isolation!
---
apiVersion: v1
kind: Service
metadata:
  name: myapp
spec:
  type: NodePort                                 # Exposed on every node
  ports:
    - port: 3000
      nodePort: 30080
---
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
data:
  username: cm9vdA==                              # base64 is NOT encryption
  password: cGFzc3dvcmQxMjM=
---
# VULNERABLE: ClusterRoleBinding — admin access for a service account
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: myapp-admin
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
# No NetworkPolicy defined — all pods can reach all pods
```

**Security flaws in this K8s manifest:**
- `image: myapp:latest` — unpinned, no digest
- Hardcoded secrets in env — visible via `kubectl get pod -o yaml` and `/proc`
- No `securityContext` — container runs as root with default capabilities
- `hostNetwork: true` — container bypasses pod network isolation
- `type: NodePort` — exposes service externally without TLS or auth
- `ClusterRoleBinding` to `cluster-admin` — full cluster access for a simple app
- No `NetworkPolicy` — default allow-all traffic model
- No resource limits — potential DoS vector
- No probes — undetected container death

---