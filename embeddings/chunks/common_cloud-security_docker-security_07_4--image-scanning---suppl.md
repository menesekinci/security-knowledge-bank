---
source: "common/cloud-security/docker-security.md"
title: "Docker Security"
heading: "4. Image Scanning & Supply Chain"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, containers, contexts, host, mounts, overview, privileged, security, table]
chunk: 7/11
---

## 4. Image Scanning & Supply Chain

Container images can contain vulnerable dependencies, malicious layers, or embedded secrets.

### Vulnerable Pattern (No Image Scanning)

```dockerfile
# VULNERABLE: Using untrusted base image with known vulnerabilities
FROM node:14  # EOL, unpatched CVEs
COPY . /app
RUN npm install  # No audit, pulls vulnerable packages
```

### Secure Image Scanning Workflow

```yaml
# SECURE: GitHub Actions with image scanning
name: Build and Scan

on:
  push:
    branches: [main]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build image
        run: docker build -t my-app:${{ github.sha }} .
      
      - name: Scan image for vulnerabilities
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: my-app:${{ github.sha }}
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
      
      - name: Sign and push
        if: success()
        run: |
          docker tag my-app:${{ github.sha }} my-registry/my-app:latest
          docker push my-registry/my-app:latest
```

```dockerfile
# SECURE: Minimal, multi-stage build with small base image
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm audit --audit-level=high

FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
RUN addgroup -S app && adduser -S app && \
    chown -R app:app /app
USER app
CMD ["node", "server.js"]
```

---