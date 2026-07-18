---
source: "common/cloud-security/ai-container-security.md"
title: "AI-Generated Container & Kubernetes Security"
heading: "2. How AI / Vibe Coding Generates This"
category: "cloud-security"
language: "common"
severity: "critical"
tags: [cloud-security, code, explanation, overview, table, vulnerability, vulnerable]
chunk: 5/11
---

## 2. How AI / Vibe Coding Generates This

### Prompt Patterns That Trigger Insecure Output

The following prompts (and their variations) reliably produce insecure Dockerfiles and Kubernetes manifests from current AI coding assistants:

**"Write me a Dockerfile for my Node.js app"**
- AI output: `FROM node:latest`, `USER root` (implicit), `RUN npm install -g`, `EXPOSE 3000`, `CMD ["npm", "start"]`
- Missing: multi-stage build, non-root user, `COPY --chown`, `.dockerignore`, health check, npm audit

**"Deploy this to Kubernetes"**
- AI output: `kind: Deployment` with no `securityContext`, `image: myapp:latest`, 1 replica, `ports` but no probes
- Missing: Pod Security Standards, resource limits, network policies, seccomp profile, read-only root filesystem

**"Create a Dockerfile for my Python Flask app"**
- AI output: `FROM python:3.11`, `RUN pip install flask` (no hashes), `ENV FLASK_APP=app.py`, `CMD python app.py`
- Missing: `pip install --no-cache-dir`, `pip freeze > requirements.txt` with hash verification, `.dockerignore`, multi-stage build

**"Docker Compose for my app with PostgreSQL"**
- AI output: `POSTGRES_PASSWORD: mypassword` hardcoded in YAML, no .env file, port 5432 exposed globally
- Missing: secrets management, network isolation between services, health checks, volume permissions

**"Kubernetes deployment with environment variables"**
- AI output: `env:` block with hardcoded values, no `ConfigMap` or `Secret` references, `imagePullPolicy: Always`
- Missing: external-secrets operator, encrypted secrets, RBAC for the service account

### Why AI Defaults to Insecure Patterns

| Factor | Explanation |
|---|---|
| **Training data bias** | Public repos contain mostly "quick start" examples with insecure defaults |
| **Compatibility priority** | AI optimizes for code that runs anywhere over code that runs securely |
| **No context of deployment** | AI doesn't know if output is for dev, staging, or production |
| **Missing security requirements** | Unless prompted explicitly, AI doesn't add security constraints |
| **Legacy pattern replication** | AI replicates patterns from pre-2020 Dockerfiles (root, latest, ADD) |

---